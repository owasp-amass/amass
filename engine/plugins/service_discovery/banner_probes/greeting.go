// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package banner_probes

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"io"
	"net"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

//go:embed protocols.json
var protocolsJSON []byte

const (
	// defaultDialTimeout is used when the caller passes a non-positive dial
	// timeout (for example in tests); production threads the configured value.
	defaultDialTimeout = 2 * time.Second
	readTimeout        = 5 * time.Second
	// maxGreeting bounds what is read and stored from a greeting.
	maxGreeting = 512
)

type protocol struct {
	ServiceType string `json:"service_type"`
	Ports       []int  `json:"ports"`
	TLSPorts    []int  `json:"tls_ports,omitempty"`
	Greeting    string `json:"greeting"`
	Source      string `json:"source"`
	TLSSource   string `json:"tls_source,omitempty"`
	re          *regexp.Regexp
}

type catalog struct {
	License   string     `json:"_license"`
	About     string     `json:"_about"`
	Protocols []protocol `json:"protocols"`
}

func (c catalog) validate() error {
	seen := map[int]string{}
	for i, p := range c.Protocols {
		if p.ServiceType == "" || len(p.Ports)+len(p.TLSPorts) == 0 || !strings.HasPrefix(p.Source, "https://") {
			return fmt.Errorf("protocol %d: service_type, ports and a source are required", i)
		}
		if len(p.TLSPorts) > 0 && !strings.HasPrefix(p.TLSSource, "https://") {
			return fmt.Errorf("protocol %s: tls_ports need a tls_source", p.ServiceType)
		}
		for _, port := range append(slices.Clone(p.Ports), p.TLSPorts...) {
			if port < 1 || port > 65535 {
				return fmt.Errorf("protocol %s: port %d is out of range", p.ServiceType, port)
			}
			if other, ok := seen[port]; ok {
				return fmt.Errorf("port %d is listed for %s and %s", port, other, p.ServiceType)
			}
			seen[port] = p.ServiceType
		}

		re, err := regexp.Compile(p.Greeting)
		if err != nil {
			return fmt.Errorf("protocol %s: %w", p.ServiceType, err)
		}
		c.Protocols[i].re = re
	}

	return nil
}

var loadCatalog = sync.OnceValues(func() (catalog, error) {
	var c catalog
	dec := json.NewDecoder(strings.NewReader(string(protocolsJSON)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("protocols.json: %w", err)
	}
	if err := c.validate(); err != nil {
		return c, fmt.Errorf("protocols.json: %w", err)
	}

	return c, nil
})

// The catalog's ports are claimed from the HTTP probes.
func init() {
	if c, err := loadCatalog(); err == nil {
		support.ClaimPorts("banner", c.probedPorts()...)
	}
}

// probedPorts lists every port the catalog probes, in order.
func (c catalog) probedPorts() []int {
	var out []int
	for _, p := range c.Protocols {
		out = append(out, p.Ports...)
		out = append(out, p.TLSPorts...)
	}
	slices.Sort(out)
	return out
}

// tlsPort reports whether the server on port expects a TLS handshake first.
func (c catalog) tlsPort(port int) bool {
	for _, p := range c.Protocols {
		if slices.Contains(p.TLSPorts, port) {
			return true
		}
	}

	return false
}

// classify returns the protocol listed for port whose greeting the line
// matches.
func (c catalog) classify(port int, line string) (protocol, bool) {
	for _, p := range c.Protocols {
		if (slices.Contains(p.Ports, port) || slices.Contains(p.TLSPorts, port)) && p.re.MatchString(line) {
			return p, true
		}
	}

	return protocol{}, false
}

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// errNoGreeting reports a connection that sent nothing before the read
// timeout, as a service that waits for the client does.
var errNoGreeting = errors.New("no greeting")

// readGreeting connects to addr and returns the first line the server
// sends. With useTLS it completes a TLS handshake first and also returns the
// certificates the server presented; they are recorded, not verified. It
// writes nothing to the connection beyond the handshake.
func readGreeting(ctx context.Context, dial dialFunc, addr string, useTLS bool, dialTO time.Duration) (string, []*x509.Certificate, error) {
	if dialTO <= 0 {
		dialTO = defaultDialTimeout
	}

	dctx, cancel := context.WithTimeout(ctx, dialTO)
	defer cancel()

	conn, err := dial(dctx, "tcp", addr)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = conn.Close() }()

	var certs []*x509.Certificate
	if useTLS {
		// The probe records whatever certificate is presented, as the HTTP
		// probe does; it never trusts the connection.
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		hctx, hcancel := context.WithTimeout(ctx, readTimeout)
		err := tc.HandshakeContext(hctx)
		hcancel()
		if err != nil {
			return "", nil, err
		}

		certs = tc.ConnectionState().PeerCertificates
		conn = tc
	}

	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	line, err := bufio.NewReader(io.LimitReader(conn, maxGreeting)).ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		if err == nil || errors.Is(err, io.EOF) {
			err = errNoGreeting
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			err = errNoGreeting
		}
		return "", certs, err
	}

	return strings.ToValidUTF8(line, ""), certs, nil
}
