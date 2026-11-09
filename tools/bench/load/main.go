// Command load measures how many queries a DNS server answers per second.
// Each of -c workers keeps one query in flight, over plain UDP, DNS over
// TLS (one connection per worker) or DNS over HTTPS (HTTP/2, eight workers
// per connection). It prints answers per second and response times.
//
// Names: -hot N cycles over N names (answered from the cache after the
// first round), -unique asks for a new name every time (never cached, spread
// over 10,000 domains, or under -zone), -names FILE cycles over the names
// in a file.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	server := flag.String("s", "127.0.0.1:53", "server address (udp, dot)")
	url := flag.String("url", "https://127.0.0.1/dns-query", "DoH URL (doh)")
	proto := flag.String("proto", "udp", "udp, dot or doh")
	workers := flag.Int("c", 64, "queries in flight")
	dur := flag.Duration("d", 10*time.Second, "how long to run")
	warm := flag.Duration("warm", 3*time.Second, "run this long first, not counted")
	hot := flag.Int("hot", 2000, "cycle over this many names")
	unique := flag.Bool("unique", false, "a new name for every query")
	zone := flag.String("zone", "", "with -unique: put the new names under this domain")
	namesFile := flag.String("names", "", "cycle over the names in this file")
	flag.Parse()

	names := make([]string, *hot)
	for i := range names {
		names[i] = fmt.Sprintf("www.bench%d.example.org", i)
	}
	if *namesFile != "" {
		var err error
		if names, err = readNames(*namesFile); err != nil {
			log.Fatal(err)
		}
	}
	var seq atomic.Uint64
	next := func() string {
		n := seq.Add(1)
		if *unique && *zone != "" {
			return fmt.Sprintf("u%d-%x.%s", n, rand.Uint32(), *zone)
		}
		if *unique {
			return fmt.Sprintf("u%d-%x.d%d.com", n, rand.Uint32(), n%10000)
		}
		return names[n%uint64(len(names))]
	}

	var clients []*http.Client
	for range max(1, *workers/8) {
		clients = append(clients, &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
			TLSClientConfig: tlsConfig(), ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 64}})
	}
	exchangers := make([]func([]byte) ([]byte, error), *workers)
	for w := range exchangers {
		var err error
		if exchangers[w], err = exchanger(*proto, *server, *url, clients[w%len(clients)]); err != nil {
			log.Fatal(err)
		}
	}

	if *warm > 0 {
		run(exchangers, next, *warm)
	}
	r := run(exchangers, next, *dur)
	slices.Sort(r.lat)
	p := func(f float64) float64 {
		if len(r.lat) == 0 {
			return 0
		}
		return float64(r.lat[int(float64(len(r.lat)-1)*f)].Microseconds()) / 1000
	}
	fmt.Printf("%.0f answers/s  p50 %.2f ms  p99 %.2f ms  failed %d", float64(len(r.lat))/dur.Seconds(), p(.5), p(.99), r.failed)
	for rc, n := range r.rcodes {
		if n > 0 && rc != 0 {
			fmt.Printf("  rcode%d %d", rc, n)
		}
	}
	fmt.Println()
}

type result struct {
	lat    []time.Duration
	failed int
	rcodes [16]int
}

func run(ex []func([]byte) ([]byte, error), next func() string, d time.Duration) result {
	var mu sync.Mutex
	var all result
	stop := time.Now().Add(d)
	var wg sync.WaitGroup
	for _, x := range ex {
		wg.Go(func() {
			var r result
			for time.Now().Before(stop) {
				t := time.Now()
				resp, err := x(query(next()))
				if err != nil {
					r.failed++
					continue
				}
				r.rcodes[resp[3]&0xf]++
				r.lat = append(r.lat, time.Since(t))
			}
			mu.Lock()
			all.lat = append(all.lat, r.lat...)
			all.failed += r.failed
			for i, n := range r.rcodes {
				all.rcodes[i] += n
			}
			mu.Unlock()
		})
	}
	wg.Wait()
	return all
}

// tlsConfig accepts any certificate: benchmarks use self-signed ones.
func tlsConfig() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

func exchanger(proto, server, url string, cl *http.Client) (func([]byte) ([]byte, error), error) {
	buf := make([]byte, 65536)
	switch proto {
	case "udp":
		c, err := net.Dial("udp", server)
		if err != nil {
			return nil, err
		}
		return func(q []byte) ([]byte, error) {
			c.Write(q)
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			for {
				n, err := c.Read(buf)
				if err != nil {
					return nil, err
				}
				if n >= 12 && buf[0] == q[0] && buf[1] == q[1] {
					return buf[:n], nil
				}
			}
		}, nil
	case "dot":
		c, err := tls.Dial("tcp", server, tlsConfig())
		if err != nil {
			return nil, err
		}
		return func(q []byte) ([]byte, error) {
			c.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil {
				return nil, err
			}
			if _, err := io.ReadFull(c, buf[:2]); err != nil {
				return nil, err
			}
			n := int(binary.BigEndian.Uint16(buf))
			if _, err := io.ReadFull(c, buf[:n]); err != nil || n < 12 {
				return nil, errors.New("short answer")
			}
			return buf[:n], nil
		}, nil
	case "doh":
		return func(q []byte) ([]byte, error) {
			q[0], q[1] = 0, 0 // RFC 8484: ID 0
			resp, err := cl.Post(url, "application/dns-message", bytes.NewReader(q))
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != http.StatusOK || len(b) < 12 {
				return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
			}
			return b, nil
		}, nil
	}
	return nil, fmt.Errorf("unknown protocol %q", proto)
}

// query builds an A query with EDNS (1232 bytes) and a random ID.
func query(name string) []byte {
	id := uint16(rand.Uint32())
	b := []byte{byte(id >> 8), byte(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 1}
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, 0, 1, 0, 1)
	return append(b, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0)
}

func readNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var names []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" && !strings.HasPrefix(t, "#") {
			names = append(names, t)
		}
	}
	if len(names) == 0 {
		return nil, errors.New("no names in " + path)
	}
	return names, sc.Err()
}
