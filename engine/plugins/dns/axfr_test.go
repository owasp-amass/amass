// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNameInZone(t *testing.T) {
	cases := []struct {
		name, zone string
		want       bool
	}{
		{"example.com", "example.com", true},
		{"www.example.com", "example.com", true},
		{"a.b.example.com.", "example.com.", true},
		{"example.com", "example.org", false},
		{"notexample.com", "example.com", false},
		{"example.com.evil.com", "example.com", false},
	}
	for _, c := range cases {
		if got := nameInZone(c.name, c.zone); got != c.want {
			t.Errorf("nameInZone(%q, %q) = %v, want %v", c.name, c.zone, got, c.want)
		}
	}
}

// axfrServer starts a TCP DNS server on an ephemeral port that answers an
// AXFR for zone with rrs when allow is true, and refuses otherwise.
func axfrServer(t *testing.T, zone string, rrs []dns.RR, allow bool) (string, func()) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Question[0].Qtype == dns.TypeAXFR && allow {
			ch := make(chan *dns.Envelope)
			tr := new(dns.Transfer)
			go func() {
				ch <- &dns.Envelope{RR: rrs}
				close(ch)
			}()
			_ = tr.Out(w, r, ch)
			return
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{Listener: l, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	time.Sleep(50 * time.Millisecond) // let the server start accepting

	return l.Addr().String(), func() { _ = srv.Shutdown() }
}

func zoneRecords(zone string) []dns.RR {
	soa, _ := dns.NewRR(zone + " 300 IN SOA ns1." + zone + " admin." + zone + " 1 7200 3600 1209600 300")
	ns, _ := dns.NewRR(zone + " 300 IN NS ns1." + zone)
	a, _ := dns.NewRR("www." + zone + " 300 IN A 192.0.2.1")
	soaEnd, _ := dns.NewRR(zone + " 300 IN SOA ns1." + zone + " admin." + zone + " 1 7200 3600 1209600 300")
	return []dns.RR{soa, ns, a, soaEnd}
}

func TestTransferZoneAllowed(t *testing.T) {
	zone := "example.com."
	addr, shutdown := axfrServer(t, zone, zoneRecords(zone), true)
	defer shutdown()

	records, ok := transferZone("example.com", addr)
	if !ok {
		t.Fatal("an allowed zone transfer was not reported as successful")
	}
	if len(records) == 0 {
		t.Fatal("the allowed zone transfer returned no records")
	}
	var sawWWW bool
	for _, rr := range records {
		if rr.Header().Name == "www.example.com." {
			sawWWW = true
		}
	}
	if !sawWWW {
		t.Errorf("the transferred records did not include www.example.com: %v", records)
	}
}

func TestTransferZoneRefused(t *testing.T) {
	zone := "example.com."
	addr, shutdown := axfrServer(t, zone, zoneRecords(zone), false)
	defer shutdown()

	if _, ok := transferZone("example.com", addr); ok {
		t.Error("a refused zone transfer was reported as successful")
	}
}

func TestTransferZoneNoServer(t *testing.T) {
	// A closed port yields a dial error, not a false exposure.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	_ = l.Close()

	if _, ok := transferZone("example.com", addr); ok {
		t.Error("a failed dial was reported as a successful transfer")
	}
}
