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

	gjar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	cjar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &Clients{
		General: &http.Client{
			Transport: genTr,
			Timeout:   1 * time.Minute,
			Jar:       gjar,
		},
		Probe: &http.Client{
			Transport: probTr,
			Timeout:   30 * time.Second,
		},
		Crawl: &http.Client{
			Transport: crwlTr,
			Timeout:   2 * time.Minute,
			Jar:       cjar,
		},
		genTr:  genTr,
		probTr: probTr,
		crwlTr: crwlTr,
	}, nil
}

func newGeneralTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           amassnet.NewDialContext(8 * time.Second),
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		// prefer correct TLS verification for APIs
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DisableCompression: false, // allow gzip
	}
}

func newProbeTransport(perHost int) *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           amassnet.NewDialContext(5 * time.Second),
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   perHost,
		IdleConnTimeout:       15 * time.Second,
		TLSHandshakeTimeout:   6 * time.Second,
		ExpectContinueTimeout: 0,
		ResponseHeaderTimeout: 8 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DisableCompression:    true,
	}
}

func newCrawlTransport() *http.Transport {
	return &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       amassnet.NewDialContext(8 * time.Second),
		ForceAttemptHTTP2: true,
		// crawling usually hits same hosts repeatedly; keep-alives pay off
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DisableCompression: false, // allow gzip to reduce bandwidth for HTML/JS/CSS
	}
}
