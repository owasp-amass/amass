// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// greeter accepts connections and sends a greeting at once, as an SSH or
// mail server does, then closes.
func greeter(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, "SSH-2.0-test\r\n")
			_ = c.Close()
		}
	}()
	return l.Addr().String()
}

// fakeSOCKS is a SOCKS5 server that connects where it is asked, or answers
// with reply when it is not zero, and records the user names it is given.
type fakeSOCKS struct {
	mu    sync.Mutex
	users []string
	hosts []string
	reply byte
	addr  string
}

func startSOCKS(t *testing.T, reply byte) *fakeSOCKS {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	s := &fakeSOCKS{reply: reply, addr: l.Addr().String()}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *fakeSOCKS) serve(c net.Conn) {
	defer func() { _ = c.Close() }()

	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}

	if strings.IndexByte(string(methods), 0x02) >= 0 {
		_, _ = c.Write([]byte{0x05, 0x02})
		ver := make([]byte, 2)
		if _, err := io.ReadFull(c, ver); err != nil {
			return
		}
		user := make([]byte, ver[1])
		_, _ = io.ReadFull(c, user)
		plen := make([]byte, 1)
		_, _ = io.ReadFull(c, plen)
		_, _ = io.ReadFull(c, make([]byte, plen[0]))
		s.mu.Lock()
		s.users = append(s.users, string(user))
		s.mu.Unlock()
		_, _ = c.Write([]byte{0x01, 0x00})
	} else {
		_, _ = c.Write([]byte{0x05, 0x00})
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		_, _ = io.ReadFull(c, b)
		host = netip.AddrFrom4([4]byte(b)).String()
	case 0x03:
		l := make([]byte, 1)
		_, _ = io.ReadFull(c, l)
		b := make([]byte, l[0])
		_, _ = io.ReadFull(c, b)
		host = string(b)
	}
	p := make([]byte, 2)
	_, _ = io.ReadFull(c, p)
	port := int(p[0])<<8 | int(p[1])

	s.mu.Lock()
	s.hosts = append(s.hosts, host)
	s.mu.Unlock()

	ok := []byte{0x05, s.reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if s.reply != 0 {
		_, _ = c.Write(ok)
		return
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}

	dst, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		ok[1] = 0x05
		_, _ = c.Write(ok)
		return
	}
	defer func() { _ = dst.Close() }()

	_, _ = c.Write(ok)
	_, _ = io.Copy(c, dst)
}

func (s *fakeSOCKS) seen() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.users...), append([]string(nil), s.hosts...)
}

// startConnectProxy is an HTTP CONNECT proxy that tunnels where it is asked,
// or answers with status when it is not 200.
func startConnectProxy(t *testing.T, status int) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()

				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				if status != http.StatusOK {
					_, _ = io.WriteString(c, "HTTP/1.1 "+strconv.Itoa(status)+" "+http.StatusText(status)+"\r\n\r\n")
					return
				}

				dst, err := net.Dial("tcp", req.Host)
				if err != nil {
					_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer func() { _ = dst.Close() }()

				// the destination's greeting can arrive in the same read as
				// the response
				greeting := make([]byte, 64)
				n, _ := dst.Read(greeting)
				_, _ = c.Write(append([]byte("HTTP/1.1 200 Connection established\r\n\r\n"), greeting[:n]...))
				_, _ = io.Copy(c, dst)
			}(c)
		}
	}()
	return l.Addr().String()
}

func readLine(t *testing.T, c net.Conn) string {
	t.Helper()

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("reading the greeting: %v", err)
	}
	return strings.TrimSpace(line)
}

func TestParseRoute(t *testing.T) {
	if r, err := ParseRoute(" ", ""); err != nil || !r.IsZero() {
		t.Errorf("ParseRoute(\"\") = %v, %v; want the zero Route", r, err)
	}

	r, err := ParseRoute("socks5h://user:secret@127.0.0.1:9050", "127.0.0.1")
	if err != nil || r.Proxy == nil || r.Proxy.Scheme != "socks5h" || r.UDP.V4 != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("ParseRoute(socks5h) = %+v, %v", r, err)
	}
	if strings.Contains(r.String(), "secret") {
		t.Errorf("the route's description shows the proxy password: %s", r)
	}

	if r, err := ParseRoute("127.0.0.1", ""); err != nil || r.Local.V4 != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("ParseRoute(127.0.0.1) = %+v, %v", r, err)
	}

	for _, bad := range []string{"ftp://127.0.0.1:21", "socks5://127.0.0.1", "http://127.0.0.1:99999",
		"socks5h://127.0.0.1:9050/path", "no-such-iface0"} {
		if _, err := ParseRoute(bad, ""); err == nil {
			t.Errorf("ParseRoute(%q) was accepted", bad)
		}
	}
	if _, err := ParseRoute("socks5h://127.0.0.1:9050", "socks5://127.0.0.1:1080"); err == nil {
		t.Error("a proxy was accepted as the UDP route")
	}

	for _, ok := range []string{"eth1", "192.0.2.10", "socks5h://tor:9050", "http://proxy.example:3128"} {
		if err := CheckRouteSpec(ok); err != nil {
			t.Errorf("CheckRouteSpec(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"eth0; rm -rf /", "gopher://x:70", "socks5://x"} {
		if err := CheckRouteSpec(bad); err == nil {
			t.Errorf("CheckRouteSpec(%q) was accepted", bad)
		}
	}
}

func TestActiveRouteFrom(t *testing.T) {
	t.Cleanup(func() { SetActiveRoute(Route{}) })

	engine := Route{Local: LocalAddrs{V4: netip.MustParseAddr("192.0.2.1")}}
	session := Route{Proxy: &url.URL{Scheme: "socks5h", Host: "127.0.0.1:9050"}}

	if r := ActiveRouteFrom(context.Background()); !r.IsZero() {
		t.Errorf("ActiveRouteFrom = %v before any setting", r)
	}

	SetActiveRoute(engine)
	if r := ActiveRouteFrom(context.Background()); r.Local != engine.Local {
		t.Errorf("ActiveRouteFrom = %v; want the engine's", r)
	}

	ctx := WithActiveRoute(context.Background(), session)
	if r := ActiveRouteFrom(ctx); r.Proxy == nil {
		t.Errorf("ActiveRouteFrom = %v; want the context's", r)
	}
	if d := ActiveTimeout(ctx, time.Second); d != 3*time.Second {
		t.Errorf("ActiveTimeout through a proxy = %v; want 3s", d)
	}
	if d := ActiveTimeout(context.Background(), time.Second); d != time.Second {
		t.Errorf("ActiveTimeout without a proxy = %v; want 1s", d)
	}
}

func TestSOCKSRoute(t *testing.T) {
	target := greeter(t)
	s := startSOCKS(t, 0)

	r := Route{Proxy: &url.URL{Scheme: "socks5h", Host: s.addr}, Isolation: "session-1"}
	c, err := r.DialContext(time.Second)(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("dial through SOCKS: %v", err)
	}
	if line := readLine(t, c); line != "SSH-2.0-test" {
		t.Errorf("greeting = %q", line)
	}
	_ = c.Close()

	// socks5h hands the name to the proxy rather than resolving it here
	_, port, _ := net.SplitHostPort(target)
	if c, err := r.DialContext(time.Second)(context.Background(), "tcp", net.JoinHostPort("localhost", port)); err == nil {
		_ = c.Close()
	}

	users, hosts := s.seen()
	if len(users) == 0 || users[0] != "session-1" {
		t.Errorf("SOCKS users = %v; want the isolation key", users)
	}
	if len(hosts) < 2 || hosts[1] != "localhost" {
		t.Errorf("SOCKS hosts = %v; want the name passed through", hosts)
	}

	// the proxy URL's own credentials win over the isolation key
	r.Proxy.User = url.UserPassword("alice", "pw")
	if c, err := r.DialContext(time.Second)(context.Background(), "tcp", target); err == nil {
		_ = c.Close()
	}
	if users, _ := s.seen(); users[len(users)-1] != "alice" {
		t.Errorf("SOCKS users = %v; want the URL's", users)
	}
}

func TestSOCKSRefusals(t *testing.T) {
	target := greeter(t)

	ruleset := startSOCKS(t, 0x02)
	r := Route{Proxy: &url.URL{Scheme: "socks5h", Host: ruleset.addr}}
	if _, err := r.DialContext(time.Second)(context.Background(), "tcp", target); !errors.Is(err, ErrRouteRefused) {
		t.Errorf("an exit policy refusal gave %v; want ErrRouteRefused", err)
	}

	refused := startSOCKS(t, 0x05)
	r.Proxy.Host = refused.addr
	_, err := r.DialContext(time.Second)(context.Background(), "tcp", target)
	if err == nil || errors.Is(err, ErrRouteRefused) {
		t.Errorf("the destination's refusal gave %v; want the target's error, not the route's", err)
	}

	// nothing listens here, so the proxy is down
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	down := l.Addr().String()
	_ = l.Close()
	r.Proxy.Host = down
	if _, err := r.DialContext(time.Second)(context.Background(), "tcp", target); !errors.Is(err, ErrRouteRefused) {
		t.Errorf("a proxy that is down gave %v; want ErrRouteRefused", err)
	}
	if err := r.CheckProxy(context.Background(), time.Second); !errors.Is(err, ErrRouteRefused) {
		t.Errorf("CheckProxy on a proxy that is down gave %v", err)
	}
}

func TestHTTPConnectRoute(t *testing.T) {
	target := greeter(t)

	r := Route{Proxy: &url.URL{Scheme: "http", Host: startConnectProxy(t, http.StatusOK)}}
	c, err := r.DialContext(time.Second)(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("dial through CONNECT: %v", err)
	}
	// the greeting arrived with the proxy's response and must not be lost
	if line := readLine(t, c); line != "SSH-2.0-test" {
		t.Errorf("greeting = %q", line)
	}
	_ = c.Close()

	r.Proxy.Host = startConnectProxy(t, http.StatusForbidden)
	if _, err := r.DialContext(time.Second)(context.Background(), "tcp", target); !errors.Is(err, ErrRouteRefused) {
		t.Errorf("a refused CONNECT gave %v; want ErrRouteRefused", err)
	}
}

func TestRouteUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()

	proxy := &url.URL{Scheme: "socks5h", Host: "127.0.0.1:9"}
	r := Route{Proxy: proxy}
	if _, err := r.DialContext(time.Second)(context.Background(), "udp", pc.LocalAddr().String()); !errors.Is(err, ErrRouteRefused) {
		t.Errorf("UDP through a proxy without a UDP route gave %v; want ErrRouteRefused", err)
	}

	r.UDP = LocalAddrs{V4: netip.MustParseAddr("127.0.0.1")}
	c, err := r.DialContext(time.Second)(context.Background(), "udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("UDP from the UDP route: %v", err)
	}
	_ = c.Close()

	// a zero Route sends active traffic like other traffic
	c, err = NewActiveDialContext(time.Second)(context.Background(), "udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("UDP without a route: %v", err)
	}
	_ = c.Close()
}
