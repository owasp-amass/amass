// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

func keys(ents []*dbt.Entity) string {
	var out []string
	for _, e := range ents {
		out = append(out, e.Asset.Key())
	}

	sort.Strings(out)
	return strings.Join(out, ",")
}

// The stored records within the TTL answer a lookup: only the asked record
// types, to assets of the asked type.
func TestLookupWithinTTL(t *testing.T) {
	sess := plugintest.NewSession(t)
	d := NewDNS().(*dnsPlugin)

	name := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	v4 := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.1"), Type: "IPv4"})
	v6 := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("2001:db8::1"), Type: "IPv6"})
	alias := sess.Asset(t, &oamdns.FQDN{Name: "edge.example.net"})
	mail := sess.Asset(t, &oamdns.FQDN{Name: "mx.example.com"})

	rec := func(rr int) *oamdns.BasicDNSRelation {
		return &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: rr, Class: 1}}
	}
	// The records the DNS plugin resolved carry its source.
	resolved := func(rel oam.Relation, to *dbt.Entity) {
		edge := sess.Edge(t, name, rel, to)
		if _, err := sess.DB().CreateEdgeProperty(context.Background(), edge,
			&general.SourceProperty{Source: d.source.Name, Confidence: 100}); err != nil {
			t.Fatal(err)
		}
	}
	resolved(rec(1), v4)
	resolved(rec(28), v6)
	resolved(rec(5), alias)
	resolved(&oamdns.PrefDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 15, Class: 1},
		Preference: 10}, mail)
	// An A record another source stored is not one the plugin resolved.
	other := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("198.51.100.7"), Type: "IPv4"})
	sess.Edge(t, name, rec(1), other)

	since := time.Now().Add(-time.Hour)
	if got := keys(d.lookupWithinTTL(sess, name, oam.IPAddress, since, d.source, oam.BasicDNSRelation, 1, 28)); got !=
		"192.0.2.1,2001:db8::1" {
		t.Errorf("A and AAAA lookup = %q", got)
	}
	if got := keys(d.lookupWithinTTL(sess, name, oam.FQDN, since, d.source, oam.BasicDNSRelation, 5)); got !=
		"edge.example.net" {
		t.Errorf("CNAME lookup = %q", got)
	}
	if got := keys(d.lookupWithinTTL(sess, name, oam.FQDN, since, d.source, oam.PrefDNSRelation, 15)); got !=
		"mx.example.com" {
		t.Errorf("MX lookup = %q", got)
	}
	// An A record's target is an address, so asking for names finds none.
	if got := d.lookupWithinTTL(sess, name, oam.FQDN, since, d.source, oam.BasicDNSRelation, 1); len(got) != 0 {
		t.Errorf("names found through A records: %q", keys(got))
	}
	// Records older than the TTL do not count.
	if got := d.lookupWithinTTL(sess, name, oam.IPAddress, time.Now().Add(time.Hour), d.source, oam.BasicDNSRelation,
		1); len(got) != 0 {
		t.Errorf("records outside the TTL were used: %q", keys(got))
	}
}
