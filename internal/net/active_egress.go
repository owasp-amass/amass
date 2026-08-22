// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// This file implements the Active egress profile. The Amass engine has two
// distinct egress profiles:
//
//   - Default egress: used by passive OSINT, data sources, and crawler/general
//     HTTP clients. This is the existing behavior.
//
//   - Active egress: used ONLY by traffic generated as a side effect of the
//     -active flag (HTTP service probes, raw TLS/JARM dials, active-derived
//     DNS queries). This traffic MUST be sent through an operator-specified
//     runtime proxy (see config.Config.ActiveProxy). When no active proxy is
//     configured the engine is fail-closed.
package net

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

func basicAuth(user, pw string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pw))
}

// ErrNoActiveEgress is returned by helpers when an active-only operation is
// attempted but no active egress profile is available. Callers MUST treat
// this as a hard failure for that operation — never fall back to direct
// dialing.
var ErrNoActiveEgress = errors.New("active egress is not configured: refusing to send active traffic over the default network")

// ActiveEgress encapsulates the network primitives used by every -active
// code path. It is intentionally narrow so that auditing the set of active
// egress users is just a matter of grepping for the field names.
//
// All fields are constructed once at session startup from the
// config.Config.ActiveProxy URL and reused for the lifetime of the session.
type ActiveEgress struct {
	// Proxy is the raw URL the operator configured. Kept verbatim for
	// logging and for components that want to construct their own
	// transports.
	Proxy string

	// DialContext dials directly through the active proxy. It is used by
	// raw TLS / JARM fingerprinting and as the dialer underneath the
	// active HTTP client and the active DNS exchange.
	//
	// Unlike NewDialContext, this dialer never falls through to a direct
	// connection: if the proxy is unreachable, the dial fails.
	DialContext DialContext

	// Client is the http.Client active service probes MUST use.
	Client *http.Client

	transport *http.Transport
}

// CloseIdleConnections releases keep-alive sockets held by the active client.
// Safe to call on a nil receiver.
func (a *ActiveEgress) CloseIdleConnections() {
	if a == nil || a.transport == nil {
		return
	}
	a.transport.CloseIdleConnections()
}

// NewActiveEgress builds an ActiveEgress from the operator-supplied proxy
// URL. Returns (nil, nil) when proxyURL is empty — callers are expected to
// treat that as "active egress not configured" and either fail closed or
// (when ActiveStrict is false) skip the active operation.
//
// The supplied probeTimeout is applied to active HTTP probes; it does not
// affect long-running active operations like crawls, which Amass currently
// does not perform in active mode.
func NewActiveEgress(proxyURL string, probeTimeout time.Duration) (*ActiveEgress, error) {
	if strings.TrimSpace(proxyURL) == "" {
		return nil, nil
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid active proxy URL %q: %w", proxyURL, err)
	}

	dial, err := buildProxyDialContext(u, 8*time.Second)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		// http.ProxyURL forces every request through the operator proxy
		// regardless of HTTP_PROXY env vars. This is intentional: the
		// active egress MUST be deterministic.
		Proxy:                 http.ProxyURL(u),
		DialContext:           dial,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: 0,
		ResponseHeaderTimeout: 15 * time.Second,
		// Service probes already accepted self-signed certs in the legacy
		// probe transport — preserve that behavior for now so the swap is
		// purely a routing change.
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		DisableCompression: true,
	}

	if probeTimeout <= 0 {
		probeTimeout = 30 * time.Second
	}

	return &ActiveEgress{
		Proxy:       proxyURL,
		DialContext: dial,
		Client: &http.Client{
			Transport: tr,
			Timeout:   probeTimeout,
		},
		transport: tr,
	}, nil
}

// buildProxyDialContext returns a DialContext that opens every connection
// through the supplied proxy URL. http/https proxies use HTTP CONNECT
// (manual implementation for non-CONNECT TCP would be ambiguous), so the
// returned dialer for those schemes will only succeed for the destinations
// the proxy is willing to relay. socks5 and socks5h both use
// golang.org/x/net/proxy.SOCKS5. That library sends hostnames verbatim
// to the proxy using the SOCKS5 DOMAINNAME address type, giving socks5h
// semantics (proxy-side resolution) automatically when the caller passes
// a hostname rather than a pre-resolved IP. Active-mode callers always
// pass hostnames or discovered IPs and never pre-resolve, so proxy-side
// resolution works correctly for both schemes.
func buildProxyDialContext(u *url.URL, perDialTimeout time.Duration) (DialContext, error) {
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		base := &net.Dialer{Timeout: perDialTimeout, KeepAlive: 30 * time.Second}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, base)
		if err != nil {
			return nil, fmt.Errorf("failed to construct SOCKS5 dialer: %w", err)
		}
		ctxDialer, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("SOCKS5 dialer does not support context")
		}
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			if !strings.HasPrefix(network, "tcp") {
				return nil, fmt.Errorf("active egress does not support network %q over SOCKS5", network)
			}
			return ctxDialer.DialContext(ctx, network, addr)
		}, nil
	case "http", "https":
		return httpConnectDialer(u, perDialTimeout), nil
	default:
		return nil, fmt.Errorf("unsupported active proxy scheme %q", u.Scheme)
	}
}

// httpConnectDialer returns a DialContext that uses HTTP CONNECT against
// the given proxy. Used for raw TLS / JARM dials when the active proxy is
// an http(s) proxy. The returned conn is the tunnelled TCP connection.
func httpConnectDialer(proxyURL *url.URL, perDialTimeout time.Duration) DialContext {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !strings.HasPrefix(network, "tcp") {
			return nil, fmt.Errorf("active egress does not support network %q over HTTP proxy", network)
		}

		dialer := &net.Dialer{Timeout: perDialTimeout, KeepAlive: 30 * time.Second}
		var rawConn net.Conn
		var err error
		proxyHost := proxyURL.Host
		if proxyURL.Scheme == "https" {
			rawConn, err = tls.DialWithDialer(dialer, "tcp", proxyHost, &tls.Config{ServerName: hostOnly(proxyHost)})
		} else {
			rawConn, err = dialer.DialContext(ctx, "tcp", proxyHost)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to reach active proxy %s: %w", proxyHost, err)
		}

		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: addr},
			Host:   addr,
			Header: make(http.Header),
		}
		if proxyURL.User != nil {
			pw, _ := proxyURL.User.Password()
			req.Header.Set("Proxy-Authorization",
				"Basic "+basicAuth(proxyURL.User.Username(), pw))
		}

		if deadline, ok := ctx.Deadline(); ok {
			_ = rawConn.SetDeadline(deadline)
		} else {
			_ = rawConn.SetDeadline(time.Now().Add(perDialTimeout))
		}

		if werr := req.Write(rawConn); werr != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("CONNECT write failed: %w", werr)
		}

		br := bufio.NewReader(rawConn)
		resp, rerr := http.ReadResponse(br, req)
		if rerr != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("CONNECT response read failed: %w", rerr)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_ = rawConn.Close()
			return nil, fmt.Errorf("active proxy CONNECT to %s rejected: %s", addr, resp.Status)
		}

		_ = rawConn.SetDeadline(time.Time{})
		// Any unread bytes (TLS data the server sent immediately) are in the
		// bufio buffer; wrap the conn so subsequent Reads see them first.
		if n := br.Buffered(); n > 0 {
			peeked, _ := br.Peek(n)
			return &bufferedConn{Conn: rawConn, buf: peeked}, nil
		}
		return rawConn, nil
	}
}

// bufferedConn is a net.Conn that prepends a pre-read byte slice before
// reading from the underlying connection. It is used to surface any bytes
// that the CONNECT response reader buffered past the response.
type bufferedConn struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	b.mu.Lock()
	if len(b.buf) > 0 {
		n := copy(p, b.buf)
		b.buf = b.buf[n:]
		b.mu.Unlock()
		return n, nil
	}
	b.mu.Unlock()
	return b.Conn.Read(p)
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
