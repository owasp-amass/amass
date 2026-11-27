// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// EgressEnv names the engine's public egress address when the -egress flag
// is not given, in place of finding it.
const EgressEnv = "AMASS_EGRESS"

// egressName is the name OpenDNS's own name servers answer with the address
// a query came from.
const egressName = "myip.opendns.com."

// egressServers are OpenDNS's name servers, asked for egressName over IPv4
// and then IPv6. A variable so tests can point them elsewhere.
var egressServers = []struct {
	addr  string
	qtype uint16
}{
	{"208.67.222.222:53", dns.TypeA},
	{"[2620:119:35::35]:53", dns.TypeAAAA},
}

// egressTimeout bounds one question to an egress server.
const egressTimeout = 5 * time.Second

// FindEgress returns the public address the engine's traffic leaves with,
// as OpenDNS's name servers see it, asking from the local addresses ctx
// names (LocalAddrsFrom), so it is the address the internet sees even
// behind NAT.
func FindEgress(ctx context.Context) (netip.Addr, error) {
	dial := NewDialContext(egressTimeout)

	var errs []error
	for _, s := range egressServers {
		a, err := askEgress(ctx, dial, s.addr, s.qtype)
		if err == nil {
			return a, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", s.addr, err))
	}
	return netip.Addr{}, errors.Join(errs...)
}

// askEgress asks one server for egressName's address of type qtype.
func askEgress(ctx context.Context, dial DialContext, server string, qtype uint16) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, egressTimeout)
	defer cancel()

	c, err := dial(ctx, "udp", server)
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = c.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}

	m := new(dns.Msg)
	m.SetQuestion(egressName, qtype)
	m.RecursionDesired = false
	conn := &dns.Conn{Conn: c}
	if err := conn.WriteMsg(m); err != nil {
		return netip.Addr{}, err
	}
	r, err := conn.ReadMsg()
	if err != nil {
		return netip.Addr{}, err
	}

	for _, rr := range r.Answer {
		var ip []byte
		switch v := rr.(type) {
		case *dns.A:
			ip = v.A
		case *dns.AAAA:
			ip = v.AAAA
		}
		if a, ok := netip.AddrFromSlice(ip); ok && a.Unmap().IsGlobalUnicast() {
			return a.Unmap(), nil
		}
	}
	return netip.Addr{}, errors.New("the answer holds no public address")
}

// engineEgress is the engine's public egress address, when known.
var engineEgress atomic.Pointer[netip.Addr]

// SetEgress records the engine's public egress address; the zero Addr
// forgets it.
func SetEgress(a netip.Addr) {
	if !a.IsValid() {
		engineEgress.Store(nil)
		return
	}
	engineEgress.Store(&a)
}

// Egress returns the engine's public egress address, when it is known.
func Egress() (netip.Addr, bool) {
	if a := engineEgress.Load(); a != nil {
		return *a, true
	}
	return netip.Addr{}, false
}
