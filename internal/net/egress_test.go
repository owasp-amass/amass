// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// egressServer answers egressName with answer, on a local UDP port.
func egressServer(t *testing.T, answer string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		if answer != "" && q.Question[0].Name == egressName {
			rr, _ := dns.NewRR(egressName + " 0 IN A " + answer)
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestFindEgress(t *testing.T) {
	saved := egressServers
	t.Cleanup(func() { egressServers = saved })

	egressServers = []struct {
		addr  string
		qtype uint16
	}{{egressServer(t, ""), dns.TypeA}, {egressServer(t, "198.51.100.7"), dns.TypeA}}
	a, err := FindEgress(context.Background())
	if err != nil || a != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("FindEgress = %v, %v; want the second server's answer", a, err)
	}

	egressServers = egressServers[:1]
	if _, err := FindEgress(context.Background()); err == nil {
		t.Error("an answer without an address was taken")
	}
}

func TestSetEgress(t *testing.T) {
	t.Cleanup(func() { SetEgress(netip.Addr{}) })
	if _, ok := Egress(); ok {
		t.Fatal("an egress is known before one is set")
	}
	SetEgress(netip.MustParseAddr("203.0.113.9"))
	if a, ok := Egress(); !ok || a.String() != "203.0.113.9" {
		t.Errorf("Egress = %v, %v", a, ok)
	}
	SetEgress(netip.Addr{})
	if _, ok := Egress(); ok {
		t.Error("the egress was not forgotten")
	}
}
