// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ErrRouteRefused reports that the active route, not the target, kept a
// connection from being made: the proxy could not be reached, it or its exit
// refused the destination, or the route carries no UDP. Such a failure says
// nothing about the target, so it is never recorded as evidence that a port
// is closed.
var ErrRouteRefused = errors.New("the active route refused the connection")

// proxySlowdown is how much longer active traffic through a proxy may take:
// the proxy, and a Tor circuit especially, adds round trips.
const proxySlowdown = 3

// Route is how active traffic, the traffic that reaches the target's own
// hosts, leaves the engine: from a network interface's addresses, or through
// a SOCKS5 or HTTP CONNECT proxy, which is itself reached the way other
// traffic is. A proxy carries TCP only, so UDP goes from the UDP interface
// when one is set, and is refused otherwise; active traffic never falls back
// to a direct connection. The zero Route sends active traffic the way other
// traffic goes.
type Route struct {
	Local LocalAddrs
	Proxy *url.URL
	UDP   LocalAddrs
	// Isolation keeps one enumeration's proxy streams apart from another's:
	// it is sent as the SOCKS user name when the proxy URL names none, which
	// Tor uses to give each enumeration its own circuits.
	Isolation string
}

// IsZero reports whether the route sends active traffic the way other
// traffic goes.
func (r Route) IsZero() bool {
	return r.Proxy == nil && r.Local.IsZero() && r.UDP.IsZero()
}

// String describes the route without the proxy's credentials.
func (r Route) String() string {
	var parts []string
	switch {
	case r.Proxy != nil:
		parts = append(parts, "proxy "+r.Proxy.Redacted())
	case !r.Local.IsZero():
		parts = append(parts, r.Local.String())
	}
	if !r.UDP.IsZero() {
		parts = append(parts, "UDP from "+r.UDP.String())
	}
	if len(parts) == 0 {
		return "the default route"
	}
	return strings.Join(parts, ", ")
}

// slowdown is how many times longer than usual active traffic on the route
// may take.
func (r Route) slowdown() time.Duration {
	if r.Proxy != nil {
		return proxySlowdown
	}
	return 1
}

// interfaceSpecPattern matches an interface name or an IP address, with an
// IPv6 zone.
var interfaceSpecPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:%-]{0,63}$`)

// CheckInterfaceSpec reports whether spec can name a network interface (an
// interface name or an IP address), without looking for it on this host.
func CheckInterfaceSpec(spec string) error {
	if !interfaceSpecPattern.MatchString(strings.TrimSpace(spec)) {
		return errors.New("the interface must be an interface name, such as eth0, or an IP address")
	}
	return nil
}

// CheckRouteSpec reports whether spec can name an active route (an interface
// or a proxy URL), without looking for the interface on this host or
// contacting the proxy.
func CheckRouteSpec(spec string) error {
	spec = strings.TrimSpace(spec)
	if strings.Contains(spec, "://") {
		_, err := parseProxy(spec)
		return err
	}
	return CheckInterfaceSpec(spec)
}

// ParseRoute returns the route that spec names: an interface (a name such as
// eth1, or one of the host's IP addresses), or a proxy URL with the scheme
// socks5h (the proxy resolves names, as Tor needs), socks5 (names are
// resolved here) or http (CONNECT). udpSpec names the interface active UDP
// leaves from. Empty specs return the zero Route.
func ParseRoute(spec, udpSpec string) (Route, error) {
	var r Route

	spec = strings.TrimSpace(spec)
	if strings.Contains(spec, "://") {
		u, err := parseProxy(spec)
		if err != nil {
			return Route{}, err
		}
		r.Proxy = u
	} else if spec != "" {
		local, err := InterfaceAddrs(spec)
		if err != nil {
			return Route{}, fmt.Errorf("the active route: %w", err)
		}
		r.Local = local
	}

	if strings.TrimSpace(udpSpec) != "" {
		if strings.Contains(udpSpec, "://") {
			return Route{}, errors.New("the active UDP route must be an interface: proxies do not carry UDP")
		}

		udp, err := InterfaceAddrs(udpSpec)
		if err != nil {
			return Route{}, fmt.Errorf("the active UDP route: %w", err)
		}
		r.UDP = udp
	}
	return r, nil
}

// parseProxy checks a proxy URL: a supported scheme, a host and a port.
func parseProxy(spec string) (*url.URL, error) {
	u, err := url.Parse(spec)
	if err != nil {
		return nil, errors.New("the active route is not a valid proxy URL")
	}

	switch u.Scheme {
	case "socks5", "socks5h", "http":
	default:
		return nil, fmt.Errorf("the proxy scheme %q is not supported; use socks5h, socks5 or http", u.Scheme)
	}
	if u.Hostname() == "" || u.Port() == "" {
		return nil, fmt.Errorf("the proxy %s must name a host and a port", u.Redacted())
	}
	if p, err := strconv.Atoi(u.Port()); err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("the proxy %s has an invalid port", u.Redacted())
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("the proxy %s must not have a path", u.Redacted())
	}
	return u, nil
}

// CheckProxy reports whether the route's proxy accepts a connection, so an
// enumeration whose proxy is down is refused before it starts rather than
// sending no active traffic. A route without a proxy is always ready.
func (r Route) CheckProxy(ctx context.Context, timeout time.Duration) error {
	if r.Proxy == nil {
		return nil
	}

	c, err := NewDialContext(timeout)(ctx, "tcp", r.Proxy.Host)
	if err != nil {
		return fmt.Errorf("%w: the proxy %s cannot be reached: %v", ErrRouteRefused, r.Proxy.Redacted(), err)
	}
	return c.Close()
}

// engineRoute is the route the engine's active traffic takes when a context
// names none.
var engineRoute atomic.Pointer[Route]

// SetActiveRoute sets the route the engine's active traffic takes when a
// context names none. The zero Route sends it the way other traffic goes.
func SetActiveRoute(r Route) {
	engineRoute.Store(&r)
}

type activeRouteKey struct{}

// WithActiveRoute returns a copy of ctx that names the route for the active
// traffic made with it. The zero Route returns ctx itself.
func WithActiveRoute(ctx context.Context, r Route) context.Context {
	if r.IsZero() {
		return ctx
	}
	return context.WithValue(ctx, activeRouteKey{}, r)
}

// ActiveRouteFrom returns the route for the active traffic made with ctx: the
// one ctx names, else the engine's, else the zero Route.
func ActiveRouteFrom(ctx context.Context) Route {
	if ctx != nil {
		if r, ok := ctx.Value(activeRouteKey{}).(Route); ok && !r.IsZero() {
			return r
		}
	}
	if r := engineRoute.Load(); r != nil {
		return *r
	}
	return Route{}
}

// ActiveTimeout returns the timeout for active traffic made with ctx: d, or
// longer when the context's route is a proxy.
func ActiveTimeout(ctx context.Context, d time.Duration) time.Duration {
	return d * ActiveRouteFrom(ctx).slowdown()
}

// NewActiveDialContext returns a dial function for active traffic: through
// the context's active route (see ActiveRouteFrom), and like NewDialContext
// when there is none. Through a proxy the timeout is lengthened (see
// ActiveTimeout). A failure of the route itself wraps ErrRouteRefused.
func NewActiveDialContext(timeout time.Duration) DialContext {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return ActiveRouteFrom(ctx).dial(ctx, timeout, network, address)
	}
}

// DialContext returns a dial function that sends through the route whatever
// context it is given.
func (r Route) DialContext(timeout time.Duration) DialContext {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return r.dial(ctx, timeout, network, address)
	}
}

func (r Route) dial(ctx context.Context, timeout time.Duration, network, address string) (net.Conn, error) {
	if strings.HasPrefix(network, "udp") {
		switch {
		case !r.UDP.IsZero():
			return NewDialContext(timeout)(WithLocalAddrs(ctx, r.UDP), network, address)
		case r.Proxy != nil:
			return nil, fmt.Errorf("%w: the proxy carries no UDP and no active UDP route is set", ErrRouteRefused)
		}
	}

	switch {
	case r.Proxy != nil:
		return r.dialProxy(ctx, timeout*proxySlowdown, network, address)
	case !r.Local.IsZero():
		return NewDialContext(timeout)(WithLocalAddrs(ctx, r.Local), network, address)
	}
	return NewDialContext(timeout)(ctx, network, address)
}

// dialProxy opens a TCP stream to address through the route's proxy.
func (r Route) dialProxy(ctx context.Context, timeout time.Duration, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("%w: the proxy carries TCP only, not %s", ErrRouteRefused, network)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	// socks5 and http proxies are given an address resolved here; socks5h
	// resolves names itself, so they never reach a resolver from this host
	if r.Proxy.Scheme != "socks5h" {
		if _, err := netip.ParseAddr(host); err != nil {
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("resolving %s: %v", host, err)
			}
			address = net.JoinHostPort(ips[0].Unmap().String(), port)
		}
	}

	conn, err := NewDialContext(timeout)(ctx, "tcp", r.Proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("%w: the proxy %s cannot be reached: %v", ErrRouteRefused, r.Proxy.Redacted(), err)
	}

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	var tunnel net.Conn
	if r.Proxy.Scheme == "http" {
		tunnel, err = httpConnect(conn, address, r.Proxy.User)
	} else {
		user, pass := r.socksAuth()
		err = socks5Connect(conn, address, user, pass)
		tunnel = conn
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	_ = conn.SetDeadline(time.Time{})
	return tunnel, nil
}

// socksAuth returns the SOCKS user name and password: the proxy URL's, else
// the route's isolation key, so each enumeration gets its own Tor circuits.
func (r Route) socksAuth() (string, string) {
	if u := r.Proxy.User; u != nil {
		pass, _ := u.Password()
		return u.Username(), pass
	}
	if r.Isolation != "" {
		return r.Isolation, "amass"
	}
	return "", ""
}

// socks5Connect asks the SOCKS5 server on conn (RFC 1928, with RFC 1929
// user name and password authentication) to connect to address.
func socks5Connect(conn net.Conn, address, user, pass string) error {
	refused := func(why string) error {
		return fmt.Errorf("%w: the SOCKS proxy %s", ErrRouteRefused, why)
	}

	methods := []byte{0x00}
	if user != "" {
		if len(user) > 255 || len(pass) > 255 {
			return errors.New("the SOCKS user name and password must be at most 255 bytes")
		}
		methods = append(methods, 0x02)
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return refused("did not take the greeting: " + err.Error())
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[0] != 0x05 {
		return refused("did not answer as SOCKS5")
	}
	switch reply[1] {
	case 0x00:
	case 0x02:
		if user == "" {
			return refused("asked for credentials, and the proxy URL has none")
		}

		auth := append([]byte{0x01, byte(len(user))}, user...)
		auth = append(append(auth, byte(len(pass))), pass...)
		if _, err := conn.Write(auth); err != nil {
			return refused("did not take the credentials: " + err.Error())
		}
		if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0x00 {
			return refused("rejected the credentials")
		}
	default:
		return refused("accepts none of the offered authentication methods")
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port in %s", address)
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip = ip.Unmap(); ip.Is4() {
			req = append(req, 0x01)
		} else {
			req = append(req, 0x04)
		}
		req = append(req, ip.AsSlice()...)
	} else {
		if len(host) > 255 {
			return fmt.Errorf("the host name %s is too long for SOCKS", host)
		}
		req = append(append(req, 0x03, byte(len(host))), host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return refused("did not take the request: " + err.Error())
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != 0x05 {
		return refused("did not answer the request")
	}
	if err := socksReplyError(head[1], address); err != nil {
		return err
	}

	// read and discard the bound address
	var n int
	switch head[3] {
	case 0x01:
		n = 4
	case 0x04:
		n = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return refused("sent a short reply")
		}
		n = int(l[0])
	default:
		return refused("sent an unknown address type")
	}
	if _, err := io.ReadFull(conn, make([]byte, n+2)); err != nil {
		return refused("sent a short reply")
	}
	return nil
}

// socksReplyError returns the error for a SOCKS5 reply code. A refusal by the
// destination itself is the target's answer; every other failure is the
// route's.
func socksReplyError(code byte, address string) error {
	why := map[byte]string{
		0x01: "general failure",
		0x02: "not allowed by the proxy's rules (a Tor exit policy, for one)",
		0x03: "network unreachable",
		0x04: "host unreachable",
		0x06: "timed out",
		0x07: "command not supported",
		0x08: "address type not supported",
	}

	switch code {
	case 0x00:
		return nil
	case 0x05:
		return fmt.Errorf("dial %s: connection refused", address)
	}
	if w, ok := why[code]; ok {
		return fmt.Errorf("%w: the SOCKS proxy could not reach %s: %s", ErrRouteRefused, address, w)
	}
	return fmt.Errorf("%w: the SOCKS proxy could not reach %s: reply %d", ErrRouteRefused, address, code)
}

// httpConnect opens a tunnel to address through the HTTP proxy on conn. A
// greeting the destination sends at once, which the response reader may have
// buffered, is kept for the caller.
func httpConnect(conn net.Conn, address string, user *url.Userinfo) (net.Conn, error) {
	req := "CONNECT " + address + " HTTP/1.1\r\nHost: " + address + "\r\n"
	if user != nil {
		pass, _ := user.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(user.Username() + ":" + pass))
		req += "Proxy-Authorization: Basic " + cred + "\r\n"
	}
	if _, err := io.WriteString(conn, req+"\r\n"); err != nil {
		return nil, fmt.Errorf("%w: the HTTP proxy did not take the request: %v", ErrRouteRefused, err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("%w: the HTTP proxy did not answer: %v", ErrRouteRefused, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: the HTTP proxy could not reach %s: %s", ErrRouteRefused, address, resp.Status)
	}

	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// bufferedConn reads first what the proxy's response reader buffered.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}
