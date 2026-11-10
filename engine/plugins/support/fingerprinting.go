// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	jarm "github.com/caffix/jarm-go"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
)

const (
	// jarmFailedProbe is how JARM records a probe that got no Server Hello.
	// RawHashToFuzzyHash returns the zero hash for the whole fingerprint if
	// any probe result has another form, such as an empty string.
	jarmFailedProbe  = "|||"
	jarmProbeTimeout = 10 * time.Second
	jarmIOTimeout    = 5 * time.Second
	// jarmReadSize is what the JARM reference implementation reads of a
	// Server Hello.
	jarmReadSize = 1484
)

// dialFunc opens a connection for one JARM probe.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// JARMFingerprint computes the JARM fingerprint of the TLS service at the
// target's port. Each of the ten probes uses its own connection, closed
// before the next; a probe that fails to connect or to get a Server Hello
// is recorded as failed, as the reference implementation does, so one
// failure does not void the fingerprint. Probes stop when the session ends.
func JARMFingerprint(sess et.Session, target oam.Asset, portrel *general.PortRelation) (string, error) {
	dial := amassnet.NewDialContext(jarmIOTimeout)
	return jarmFingerprint(sess.Ctx(), func(ctx context.Context, network, address string) (net.Conn, error) {
		sess.NetSem().Acquire()
		defer sess.NetSem().Release()

		return dial(ctx, network, address)
	}, target, portrel)
}

func jarmFingerprint(ctx context.Context, dial dialFunc, target oam.Asset, portrel *general.PortRelation) (string, error) {
	if portrel == nil || portrel.PortNumber < 1 || portrel.PortNumber > 65535 {
		return "", errors.New("a valid TCP port is required")
	}

	var host string
	if fqdn, ok := target.(*oamdns.FQDN); ok {
		host = fqdn.Name
	} else if ip, ok := target.(*network.IPAddress); ok {
		host = ip.Address.String()
	} else {
		return "", errors.New("target must be a FQDN or IPAddress")
	}

	addr := net.JoinHostPort(host, strconv.Itoa(portrel.PortNumber))
	probes := jarm.GetProbes(host, portrel.PortNumber)
	results := make([]string, 0, len(probes))
	for _, probe := range probes {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		results = append(results, jarmProbe(ctx, dial, addr, probe))
	}

	hash := jarm.RawHashToFuzzyHash(strings.Join(results, ","))
	if hash == jarm.ZeroHash {
		return "", fmt.Errorf("no JARM probe got a Server Hello from %s", addr)
	}

	return hash, nil
}

// jarmProbe sends one probe and returns its result, or jarmFailedProbe.
func jarmProbe(ctx context.Context, dial dialFunc, addr string, probe jarm.JarmProbeOptions) string {
	pctx, cancel := context.WithTimeout(ctx, jarmProbeTimeout)
	defer cancel()

	c, err := dial(pctx, "tcp", addr)
	if err != nil {
		return jarmFailedProbe
	}
	defer func() { _ = c.Close() }()

	_ = c.SetWriteDeadline(time.Now().Add(jarmIOTimeout))
	if _, err := c.Write(jarm.BuildProbe(probe)); err != nil {
		return jarmFailedProbe
	}

	_ = c.SetReadDeadline(time.Now().Add(jarmIOTimeout))
	buf := make([]byte, jarmReadSize)
	// A Server Hello read before the server closed the connection is still
	// usable, so only an empty read fails the probe.
	n, _ := c.Read(buf)
	if n == 0 {
		return jarmFailedProbe
	}

	ans, err := jarm.ParseServerHello(buf[:n], probe)
	if err != nil {
		return jarmFailedProbe
	}

	return ans
}
