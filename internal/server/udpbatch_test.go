package server

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

// Answers come back on IPv4, IPv6 and dual-stack (":port") sockets alike,
// one query or many at once (which the batched path sends together).
func TestUDPBatchFamilies(t *testing.T) {
	has6 := false
	if c, err := net.ListenPacket("udp6", "[::1]:0"); err == nil {
		c.Close()
		has6 = true
	}
	// plain DNS binds UDP and TCP: ports free for both
	_, port, _ := net.SplitHostPort(freeAddrOn(t, ""))
	listen := []string{"127.0.0.1:0", ":" + port}
	ask := []string{"127.0.0.1:" + port}
	if has6 {
		v6 := freeAddrOn(t, "::1")
		listen = append(listen, v6)
		ask = append(ask, v6, "[::1]:"+port)
	} else {
		t.Log("no IPv6 here: IPv4 and the all-addresses socket only")
	}
	s, _, path := start(t, "")
	writeListen(t, path, listen)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	for _, addr := range ask {
		var wg sync.WaitGroup
		errs := make(chan error, 64)
		for i := range 64 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				name := fmt.Sprintf("b%d.test", i%8)
				resp, err := udpAsk(t, addr, dnstest.Query(uint16(i), name, m.TypeA, false, false), 2*time.Second)
				if err != nil {
					errs <- fmt.Errorf("%s query %d: %w", addr, i, err)
					return
				}
				if p := dnstest.Parse(t, resp); p.ID != uint16(i) || p.AN != 1 {
					errs <- fmt.Errorf("%s query %d: %+v", addr, i, p)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	}
}

func writeListen(t *testing.T, path string, addrs []string) {
	t.Helper()
	src, err := readFile(path)
	if err != nil {
		t.Fatal(err)
	}
	q := make([]string, len(addrs))
	for i, a := range addrs {
		q[i] = fmt.Sprintf("%q", a)
	}
	src = strings.Replace(src, `listen = ["127.0.0.1:0"]`, "listen = ["+strings.Join(q, ", ")+"]", 1)
	if err := writeFile(path, src); err != nil {
		t.Fatal(err)
	}
}

func readFile(p string) (string, error) { b, err := os.ReadFile(p); return string(b), err }
func writeFile(p, s string) error       { return os.WriteFile(p, []byte(s), 0o640) }
