package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	log "github.com/sirupsen/logrus"

	"github.com/hdm/jarm-go"
)

// Version is set by the goreleaser build
var Version = "dev"

var defaultPorts = flag.String("p", "443", "default ports")
var workerCount = flag.Int("w", 256, "worker count")
var quietMode = flag.Bool("q", false, "quiet mode")
var retries = flag.Int("r", 3, "number of times to retry dialing")
var timeout = flag.Int("t", 2, "connection timeout in seconds")
var inputFilePath = flag.String("i", "", "input file path")

// ValidPort determines if a port number is valid
func ValidPort(pnum int) bool {
	if pnum < 1 || pnum > 65535 {
		return false
	}
	return true
}

// CrackPortsWithDefaults turns a comma-delimited port list into an array, handling defaults
func CrackPortsWithDefaults(pspec string, defaults []uint16) ([]int, error) {
	results := []int{}

	// Use a map to dedup and shuffle ports
	ports := make(map[int]bool)

	bits := strings.Split(pspec, ",")
	for _, bit := range bits {

		// Support the magic strings "default" and "defaults"
		if bit == "default" || bit == "defaults" {
			for _, pnum := range defaults {
				ports[int(pnum)] = true
			}
			continue
		}

		// Split based on dash
		prange := strings.Split(bit, "-")

		// Scan all ports if the specifier is a single dash
		if bit == "-" {
			prange = []string{"1", "65535"}
		}

		// No port range
		if len(prange) == 1 {
			pnum, err := strconv.Atoi(bit)
			if err != nil || !ValidPort(pnum) {
				return results, fmt.Errorf("invalid port %s", bit)
			}
			// Record the valid port
			ports[pnum] = true
			continue
		}

		if len(prange) != 2 {
			return results, fmt.Errorf("invalid port range %s (%d)", prange, len(prange))
		}

		pstart, err := strconv.Atoi(prange[0])
		if err != nil || !ValidPort(pstart) {
			return results, fmt.Errorf("invalid start port %d", pstart)
		}

		pstop, err := strconv.Atoi(prange[1])
		if err != nil || !ValidPort(pstop) {
			return results, fmt.Errorf("invalid stop port %d", pstop)
		}

		if pstart > pstop {
			return results, fmt.Errorf("invalid port range %d-%d", pstart, pstop)
		}

		for pnum := pstart; pnum <= pstop; pnum++ {
			ports[pnum] = true
		}
	}

	// Create the results from the map
	for port := range ports {
		results = append(results, port)
	}
	return results, nil
}

// Fingerprint probes a single host/port
func Fingerprint(t target, och chan result) {

	results := []string{}
	for _, probe := range jarm.GetProbes(t.Host, t.Port) {
		dialer := proxy.FromEnvironmentUsing(&net.Dialer{Timeout: time.Second * time.Duration(*timeout)})
		addr := net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port))

		c := net.Conn(nil)
		n := 0

		for c == nil && n <= t.Retries {
			if c, _ = dialer.Dial("tcp", addr); c != nil || t.Retries == 0 {
				break
			}

			bo := t.Backoff
			if bo == nil {
				bo = DefaultBackoff
			}

			time.Sleep(bo(n, t.Retries))

			n++
		}

		if c == nil {
			return
		}

		data := jarm.BuildProbe(probe)
		c.SetWriteDeadline(time.Now().Add(time.Second * 5))
		_, err := c.Write(data)
		if err != nil {
			results = append(results, "")
			c.Close()
			continue
		}

		c.SetReadDeadline(time.Now().Add(time.Second * 5))
		buff := make([]byte, 1484)
		c.Read(buff)
		c.Close()

		ans, err := jarm.ParseServerHello(buff, probe)
		if err != nil {
			results = append(results, "")
			continue
		}

		results = append(results, ans)
	}

	och <- result{
		Target: t,
		Hash:   jarm.RawHashToFuzzyHash(strings.Join(results, ",")),
	}
}

var DefualtBackoff = func(r, m int) time.Duration {
	return time.Second
}

type target struct {
	Host string
	Port int

	Retries int
	Backoff func(r, m int) time.Duration
}

type result struct {
	Target target
	Hash   string
	Error  error
}

func main() {
	flag.Parse()

	if *inputFilePath == "" {
		log.Fatalf("usage: ./jarm -p <ports> -i <input_file_path>")
	}

	if *workerCount < 1 {
		log.Fatalf("invalid worker count: %d", *workerCount)
	}

	if *quietMode {
		dn, _ := os.Create(os.DevNull)
		log.SetOutput(dn)
	}

	defaultPorts, err := CrackPortsWithDefaults(*defaultPorts, []uint16{})
	if err != nil {
		log.Fatalf("invalid ports: %s", err)
	}

	tch := make(chan target, *workerCount)
	och := make(chan result, *workerCount)

	wgo := sync.WaitGroup{}

	// Output consolidator
	wgo.Add(1)
	go func() {
		defer wgo.Done()
		for o := range och {
			if o.Error != nil {
				log.Printf("failed to scan %s:%d: %s", o.Target.Host, o.Target.Port, o.Error)
				continue
			}
			if len(o.Target.Host) > 24 {
				fmt.Printf("JARM\t%s:%d\t%s\n", o.Target.Host, o.Target.Port, o.Hash)
			} else {
				fmt.Printf("JARM\t%24s:%d\t%s\n", o.Target.Host, o.Target.Port, o.Hash)
			}
		}
	}()

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < *workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tch {
				Fingerprint(t, och)
			}
		}()
	}

	// Process targets from file
	file, err := os.Open(*inputFilePath)
	if err != nil {
		log.Fatalf("failed to open file: %s", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		host := scanner.Text()
		processHost(host, defaultPorts, tch, *retries)
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("error reading from file: %s", err)
	}

	// Close the target channel and wait for workers to finish
	close(tch)
	wg.Wait()

	// Wait for output to finish
	close(och)
	wgo.Wait()
}



func processHost(host string, defaultPorts []int, tch chan target, retries int) {
	ports := defaultPorts
	for _, port := range ports {
		tch <- target{
			Host:    host,
			Port:    port,
			Retries: retries,
		}
	}
}
