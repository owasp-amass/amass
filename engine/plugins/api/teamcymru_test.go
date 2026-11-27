// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/time/rate"
)

func cymruEvent(t *testing.T, sess *plugintest.Session, addr string) *et.Event {
	t.Helper()

	a := netip.MustParseAddr(addr)
	typ := "IPv4"
	if a.Is6() {
		typ = "IPv6"
	}
	ent := sess.Asset(t, &oamnet.IPAddress{Address: a, Type: typ})
	return &et.Event{Name: addr, Entity: ent, Session: sess, Dispatcher: &plugintest.Dispatcher{}}
}

// Team Cymru is asked once per prefix: an address inside a prefix it already
// gave this session is linked to that netblock without another query, and a
// reserved address is never asked about.
func TestTeamCymruAsksOncePerPrefix(t *testing.T) {
	sess := apiSession(t)
	d := sess.DNS(t)
	d.Add(t, `181.4.237.72.origin.asn.cymru.com. 300 IN TXT "6461 | 72.237.4.0/24 | US | arin | 2006-01-01"`)

	c := NewTeamCymru().(*teamCymru)
	c.rlimit = rate.NewLimiter(rate.Inf, 1)

	for _, addr := range []string{"72.237.4.181", "72.237.4.180", "72.237.4.179", "10.1.2.3", "100.64.0.1"} {
		if err := c.check(cymruEvent(t, sess, addr)); err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
	}

	if n := len(d.Queries()); n != 1 {
		t.Fatalf("Team Cymru was asked %d times, want once: %v", n, d.Queries())
	}
	if d.Asked(dns.TypeTXT, "181.4.237.72.origin.asn.cymru.com") != 1 {
		t.Errorf("the first address was not asked about: %v", d.Queries())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nbs, err := sess.DB().FindEntitiesByContent(ctx, oam.Netblock, time.Time{}, 0,
		dbt.ContentFilters{"cidr": "72.237.4.0/24"})
	if err != nil || len(nbs) != 1 {
		t.Fatalf("netblock: %v, %v", nbs, err)
	}
	edges, err := sess.DB().OutgoingEdges(ctx, nbs[0], time.Time{}, "contains")
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 3 {
		t.Errorf("the netblock contains %d addresses, want the 3 routed ones", len(edges))
	}
}

// An address the service has no route for is not asked about again within
// the TTL.
func TestTeamCymruRemembersNoRoute(t *testing.T) {
	sess := apiSession(t)
	d := sess.DNS(t)

	c := NewTeamCymru().(*teamCymru)
	c.rlimit = rate.NewLimiter(rate.Inf, 1)

	e := cymruEvent(t, sess, "198.51.100.7")
	for range 2 {
		if err := c.check(e); err != nil {
			t.Fatal(err)
		}
	}
	if n := d.Asked(dns.TypeTXT, "7.100.51.198.origin.asn.cymru.com"); n != 1 {
		t.Errorf("an address without a route was asked about %d times, want once", n)
	}
}
