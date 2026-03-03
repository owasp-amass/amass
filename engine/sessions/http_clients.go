// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"time"

	amassnet "github.com/owasp-amass/amass/v5/internal/net"
)

// Clients bundles the three clients + transports so you can close idle conns.
type Clients struct {
	General *http.Client
	Probe   *http.Client
	Crawl   *http.Client
	genTr   *http.Transport
	probTr  *http.Transport
	crwlTr  *http.Transport
}

// CloseIdleConnections is useful on session/engine shutdown.
// It does not kill in-flight requests, but it releases keep-alive sockets.
func (c *Clients) CloseIdleConnections() {
	if c.genTr != nil {
		c.genTr.CloseIdleConnections()
	}
	if c.probTr != nil {
		c.probTr.CloseIdleConnections()
	}
	if c.crwlTr != nil {
		c.crwlTr.CloseIdleConnections()
	}
}

// NewClients returns three tuned clients: API, Probe, Crawl.
func NewClients(perHost int) (*Clients, error) {
	genTr := newGeneralTransport()
	probTr := newProbeTransport(perHost)
	crwlTr := newCrawlTransport()

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &Clients{
		General: &http.Client{Transport: genTr, Timeout: 20 * time.Second},
		Probe: &http.Client{
			Transport: probTr,
			// for probes, prefer per-request context timeouts; keep a hard cap anyway
			Timeout: 8 * time.Second,
		},
		Crawl: &http.Client{
			Transport: crwlTr,
			// crawls can legitimately take longer. Use request contexts to bound if needed
			Timeout: 45 * time.Second,
			Jar:     jar,
		},
		genTr:  genTr,
		probTr: probTr,
		crwlTr: crwlTr,
	}, nil
}

func newGeneralTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           amassnet.NewDialContext(5 * time.Second),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   20,
		MaxConnsPerHost:       50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		// prefer correct TLS verification for APIs
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DisableCompression: false, // allow gzip
	}
}

func newProbeTransport(perHost int) *http.Transport {
	return &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       amassnet.NewDialContext(2 * time.Second),
		ForceAttemptHTTP2: true,
		// keep this lower: probes spray across many hosts; idle pools become “memory”
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   2,
		MaxConnsPerHost:       10,
		IdleConnTimeout:       20 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ExpectContinueTimeout: 0,
		ResponseHeaderTimeout: 4 * time.Second,
		// often you’ll hit junk certs during probing; keep verification on by default.
		// if you *must* allow insecure probing, fork a separate transport with InsecureSkipVerify=true
		// but be intentional about it
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DisableCompression: true, // avoid spending CPU on gzip for tiny probe responses
	}
}

func newCrawlTransport() *http.Transport {
	return &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       amassnet.NewDialContext(6 * time.Second),
		ForceAttemptHTTP2: true,
		// crawling usually hits same hosts repeatedly; keep-alives pay off
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   32,
		MaxConnsPerHost:       32,
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   6 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 12 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DisableCompression: false, // allow gzip to reduce bandwidth for HTML/JS/CSS
	}
}
