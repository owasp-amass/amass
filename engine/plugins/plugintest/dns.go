// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugintest

import (
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
)

// DNS is the fake DNS of a test session (Session.DNS): a resolver on the
// loopback interface that answers from the records the test adds.
type DNS struct {
	mu      sync.Mutex
	records map[string][]dns.RR
	queries []string
	// failing are zones whose names all answer SERVFAIL (Fail)
	failing []string
	// Addr is the resolver's address, host:port.
	Addr string
}

// DNS returns the session's fake DNS. The first call starts a resolver on
// the loopback interface, sends the session's queries and wildcard tests to
// it, and removes the engine's limit on queries per resolver until the test
// ends. A name the test added no records for answers NXDOMAIN; a name with
// records, but none of the asked type, answers NOERROR with no answer. A
// record whose owner is "*.zone" answers every name in the zone without
// records of its own.
func (s *Session) DNS(t testing.TB) *DNS {
	t.Helper()

	s.dnsOnce.Do(func() {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("the fake DNS did not start: %v", err)
		}

		d := &DNS{records: make(map[string][]dns.RR), Addr: pc.LocalAddr().String()}
		srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(d.serve)}
		go func() { _ = srv.ActivateAndServe() }()
		t.Cleanup(func() { _ = srv.Shutdown() })

		r, err := amassdns.NewResolvers([]string{d.Addr}, d.Addr, amassnet.LocalAddrs{})
		if err != nil {
			t.Fatalf("the session's resolvers were not created: %v", err)
		}
		t.Cleanup(r.Stop)
		s.ctx = amassdns.WithResolvers(s.ctx, r)

		qps := amassdns.ResolverQPS()
		amassdns.SetResolverQPS(0)
		t.Cleanup(func() { amassdns.SetResolverQPS(qps) })
		s.dns = d
	})
	return s.dns
}

// Add adds records in zone file form, such as "www.example.com. 300 IN A 192.0.2.1".
func (d *DNS) Add(t testing.TB, records ...string) {
	t.Helper()

	d.mu.Lock()
	defer d.mu.Unlock()

	for _, r := range records {
		rr, err := dns.NewRR(r)
		if err != nil || rr == nil {
			t.Fatalf("the record %q does not parse: %v", r, err)
		}
		name := strings.ToLower(rr.Header().Name)
		d.records[name] = append(d.records[name], rr)
	}
}

// Fail makes every name in the zone, and the zone itself, answer SERVFAIL,
// as the servers of a zone that does not answer queries do.
func (d *DNS) Fail(zone string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.failing = append(d.failing, dns.Fqdn(strings.ToLower(zone)))
}

// Queries returns the queries asked so far, each as its type and name, such
// as "A www.example.com.".
func (d *DNS) Queries() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	return append([]string(nil), d.queries...)
}

// Asked reports how many times the query of the type and name was asked.
func (d *DNS) Asked(qtype uint16, name string) int {
	want := dns.TypeToString[qtype] + " " + dns.Fqdn(strings.ToLower(name))

	var n int
	for _, q := range d.Queries() {
		if q == want {
			n++
		}
	}
	return n
}

func (d *DNS) serve(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	if len(req.Question) == 1 {
		q := req.Question[0]
		name := strings.ToLower(q.Name)

		d.mu.Lock()
		d.queries = append(d.queries, dns.TypeToString[q.Qtype]+" "+name)
		records, found := d.records[name]
		if !found {
			if i := strings.Index(name, "."); i >= 0 {
				records, found = d.records["*"+name[i:]]
			}
		}
		failing := false
		for _, zone := range d.failing {
			if name == zone || strings.HasSuffix(name, "."+zone) {
				failing = true
			}
		}
		d.mu.Unlock()

		if failing {
			resp.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(resp)
			return
		}
		if !found {
			resp.Rcode = dns.RcodeNameError
		}
		for _, rr := range records {
			if rr.Header().Rrtype != q.Qtype {
				continue
			}
			answer := dns.Copy(rr)
			answer.Header().Name = q.Name
			resp.Answer = append(resp.Answer, answer)
		}
	}
	_ = w.WriteMsg(resp)
}
