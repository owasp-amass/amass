// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

func ipAddr(s string) *oamnet.IPAddress {
	addr := netip.MustParseAddr(s)
	if addr.Is4() {
		return &oamnet.IPAddress{Address: addr, Type: "IPv4"}
	}
	return &oamnet.IPAddress{Address: addr, Type: "IPv6"}
}

// dnsTargets returns the keys of the assets the entity's dns_record edges
// lead to, sorted, and fails when an edge lacks the source.
func dnsTargets(t *testing.T, sess *plugintest.Session, from *dbt.Entity, label string, src *et.Source) string {
	t.Helper()

	ctx := context.Background()
	edges, err := sess.DB().OutgoingEdges(ctx, from, time.Time{}, label)
	if err != nil {
		return ""
	}

	var ents []*dbt.Entity
	for _, edge := range edges {
		if !support.Sourced(ctx, sess, edge, time.Time{}, src) {
			t.Errorf("the %s edge to %s is not tagged with %s", label, edge.ToEntity.ID, src.Name)
		}
		if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil {
			ents = append(ents, a)
		}
	}
	return keys(ents)
}

func dnsSession(t *testing.T) (*plugintest.Session, *plugintest.DNS, *dnsPlugin) {
	t.Helper()

	sess := plugintest.NewSession(t)
	sess.TTL(60)
	return sess, sess.DNS(t), NewDNS().(*dnsPlugin)
}

func TestIPHandlerStoresTheAddresses(t *testing.T) {
	sess, fake, d := dnsSession(t)
	fake.Add(t,
		"www.example.com. 300 IN A 192.0.2.10",
		"www.example.com. 300 IN A 192.0.2.11",
		"www.example.com. 300 IN AAAA 2001:db8::10",
	)
	ip := newIP(d)

	www := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	disp := &plugintest.Dispatcher{}
	e := &et.Event{Entity: www, Session: sess, Dispatcher: disp}
	if err := ip.check(e); err != nil {
		t.Fatal(err)
	}

	if got := dnsTargets(t, sess, www, "dns_record", ip.source); got != "192.0.2.10,192.0.2.11,2001:db8::10" {
		t.Errorf("addresses = %q", got)
	}
	if n := len(disp.Events()); n != 3 {
		t.Errorf("dispatched %d addresses, want 3: %v", n, disp.Names())
	}
	if !support.HasDNSRecordType(e, int(dns.TypeA)) || !support.HasDNSRecordType(e, int(dns.TypeAAAA)) {
		t.Error("the event does not record that the name has A and AAAA records")
	}

	// Within the time to live, the stored records answer without new queries.
	asked := len(fake.Queries())
	again := &plugintest.Dispatcher{}
	if err := ip.check(&et.Event{Entity: www, Session: sess, Dispatcher: again}); err != nil {
		t.Fatal(err)
	}
	if n := len(fake.Queries()); n != asked {
		t.Errorf("the second check asked %d more queries", n-asked)
	}
	if n := len(again.Events()); n != 3 {
		t.Errorf("the second check dispatched %d addresses, want 3", n)
	}
}

func TestIPHandlerSkipsAnAlias(t *testing.T) {
	sess, fake, d := dnsSession(t)
	fake.Add(t, "www.example.com. 300 IN A 192.0.2.10")

	www := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	e := &et.Event{Entity: www, Session: sess, Dispatcher: &plugintest.Dispatcher{}}
	support.AddDNSRecordType(e, int(dns.TypeCNAME))
	if err := newIP(d).check(e); err != nil {
		t.Fatal(err)
	}
	if n := fake.Asked(dns.TypeA, "www.example.com"); n != 0 {
		t.Errorf("an alias's addresses were asked for %d times; they come from its target", n)
	}
}

func TestCNAMEHandlerFollowsTheAliasIntoAWildcardZone(t *testing.T) {
	sess, fake, d := dnsSession(t)
	fake.Add(t,
		"www.example.com. 300 IN CNAME edge.cdn.example.net.",
		"*.cdn.example.net. 300 IN A 198.51.100.7",
	)
	cname, ip := newCNAME(d), newIP(d)

	www := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	disp := &plugintest.Dispatcher{}
	e := &et.Event{Entity: www, Session: sess, Dispatcher: disp}
	if err := cname.check(e); err != nil {
		t.Fatal(err)
	}
	if got := dnsTargets(t, sess, www, "dns_record", cname.source); got != "edge.cdn.example.net" {
		t.Fatalf("alias target = %q", got)
	}
	if !support.HasDNSRecordType(e, int(dns.TypeCNAME)) {
		t.Error("the event does not record the CNAME")
	}

	events := disp.Events()
	if len(events) != 1 {
		t.Fatalf("dispatched %v", disp.Names())
	}
	meta, ok := events[0].Meta.(*support.FQDNMeta)
	if !ok || !meta.FromRecord {
		t.Fatalf("the target's event meta = %#v; want it marked as named by a record", events[0].Meta)
	}

	// The target is answered by its zone's wildcard, but a record named it, so
	// its address is kept.
	target := events[0]
	target.Dispatcher = &plugintest.Dispatcher{}
	if err := ip.check(target); err != nil {
		t.Fatal(err)
	}
	if got := dnsTargets(t, sess, target.Entity, "dns_record", ip.source); got != "198.51.100.7" {
		t.Errorf("the target's address = %q", got)
	}

	// A guessed name in the same zone is suppressed.
	guess := sess.Asset(t, &oamdns.FQDN{Name: "guess.cdn.example.net"})
	if err := ip.check(&et.Event{Entity: guess, Session: sess, Dispatcher: &plugintest.Dispatcher{}}); err != nil {
		t.Fatal(err)
	}
	if got := dnsTargets(t, sess, guess, "dns_record", ip.source); got != "" {
		t.Errorf("a wildcard answer was stored for a guessed name: %q", got)
	}
}

func TestReverseHandlerStoresThePTRName(t *testing.T) {
	sess, fake, d := dnsSession(t)
	fake.Add(t, "7.113.0.203.in-addr.arpa. 300 IN PTR mail.example.com.")
	rev := NewReverse(d)

	addr := sess.Asset(t, ipAddr("203.0.113.7"))
	disp := &plugintest.Dispatcher{}
	if err := rev.check(&et.Event{Entity: addr, Session: sess, Dispatcher: disp}); err != nil {
		t.Fatal(err)
	}

	if got := dnsTargets(t, sess, addr, "ptr_record", d.source); got != "7.113.0.203.in-addr.arpa" {
		t.Fatalf("the address's reverse name = %q", got)
	}
	ptr, err := sess.DB().FindEntitiesByContent(context.Background(), oam.FQDN, time.Time{}, 1,
		dbt.ContentFilters{"name": "7.113.0.203.in-addr.arpa"})
	if err != nil || len(ptr) != 1 {
		t.Fatalf("the reverse name was not stored: %v", err)
	}
	if got := dnsTargets(t, sess, ptr[0], "dns_record", d.source); got != "mail.example.com" {
		t.Errorf("the PTR target = %q", got)
	}
	if names := disp.Names(); len(names) != 2 {
		t.Errorf("dispatched %v; want the reverse name and its target", names)
	}
}
