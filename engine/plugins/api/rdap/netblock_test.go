// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/openrdap/rdap"
	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

func ipNetwork() *rdap.IPNetwork {
	return &rdap.IPNetwork{Handle: "NET-192-0-2-0-1", StartAddress: "192.0.2.0", EndAddress: "192.0.2.255",
		Name: "TEST-NET-1", Type: "DIRECT ALLOCATION", Country: "US", ParentHandle: "NET-192-0-0-0-0",
		Port43: "whois.arin.net", Status: []string{"active"},
		Events: []rdap.Event{{Action: "registration", Date: "2010-01-01T00:00:00Z"},
			{Action: "last changed", Date: "2024-06-01T12:00:00Z"}}}
}

func TestNetblockStore(t *testing.T) {
	sess := plugintest.NewSession(t)
	rd := NewRDAP().(*rdapPlugin)
	nb := &netblock{name: "RDAP-Netblock-Handler", plugin: rd}
	block := sess.Asset(t, &network.Netblock{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Type: "IPv4"})
	e := &et.Event{Session: sess}

	rec := nb.store(e, ipNetwork(), block)
	if rec == nil {
		t.Fatal("a complete RDAP response was not stored")
	}

	r, ok := rec.Asset.(*oamreg.IPNetRecord)
	if !ok || r.Handle != "NET-192-0-2-0-1" || r.StartAddress.String() != "192.0.2.0" ||
		r.EndAddress.String() != "192.0.2.255" || r.WhoisServer != "whois.arin.net" ||
		r.CreatedDate == "" || r.UpdatedDate == "" {
		t.Errorf("stored record %+v", rec.Asset)
	}

	ctx := context.Background()
	edges, err := sess.DB().OutgoingEdges(ctx, block, time.Time{}, "registration")
	if err != nil || len(edges) != 1 || edges[0].ToEntity.ID != rec.ID {
		t.Fatalf("registration edge: %v, %v", edges, err)
	}

	tags, err := sess.DB().FindEntityTags(ctx, rec, time.Time{})
	found := false
	for _, tag := range tags {
		if p, ok := tag.Property.(*general.SourceProperty); ok && p.Source == rd.source.Name {
			found = true
		}
	}
	if err != nil || !found {
		t.Errorf("the record lacks its RDAP source: %v, %v", tags, err)
	}
}

// A response missing what the record needs, or carrying a malformed
// address, is not stored, and does not panic the handler.
func TestNetblockStoreRejectsIncompleteResponses(t *testing.T) {
	sess := plugintest.NewSession(t)
	nb := &netblock{name: "RDAP-Netblock-Handler", plugin: NewRDAP().(*rdapPlugin)}
	block := sess.Asset(t, &network.Netblock{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Type: "IPv4"})
	e := &et.Event{Session: sess}

	noEvents := ipNetwork()
	noEvents.Events = noEvents.Events[:1]
	badStart := ipNetwork()
	badStart.StartAddress = ""
	badEnd := ipNetwork()
	badEnd.EndAddress = "192.0.2.256"

	for name, resp := range map[string]*rdap.IPNetwork{"no last changed event": noEvents,
		"no start address": badStart, "malformed end address": badEnd} {
		if rec := nb.store(e, resp, block); rec != nil {
			t.Errorf("%s: stored %+v", name, rec.Asset)
		}
	}
}

func TestGetJSONLink(t *testing.T) {
	rd := NewRDAP().(*rdapPlugin)
	links := []rdap.Link{{Type: "text/html", Href: "https://rdap.example/ip/192.0.2.0.html"},
		{Type: "application/rdap+json", Href: "https://rdap.example/entity/EX-1"}}
	if u := rd.getJSONLink(links); u == nil || u.Raw != "https://rdap.example/entity/EX-1" {
		t.Errorf("getJSONLink = %+v", u)
	}
	if u := rd.getJSONLink(links[:1]); u != nil {
		t.Errorf("a link that is not RDAP JSON was used: %+v", u)
	}
}
