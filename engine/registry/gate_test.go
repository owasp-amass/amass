// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// gated sends the assets through a pipeline of their type holding only h and
// returns the keys of those the handler was run on, sorted.
func gated(t *testing.T, sess *plugintest.Session, h *et.Handler, ents ...*dbt.Entity) []string {
	t.Helper()

	var mu sync.Mutex
	var handled []string
	h.Position, h.MaxInstances = 5, 1
	h.Callback = func(e *et.Event) error {
		mu.Lock()
		defer mu.Unlock()
		handled = append(handled, e.Entity.Asset.Key())
		return nil
	}
	r := NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil))).(*registry)
	if err := r.RegisterHandler(h); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ap, err := r.BuildAssetPipeline(ctx, h.EventType)
	if err != nil {
		t.Fatal(err)
	}
	exit := make(chan *et.EventDataElement, len(ents))
	for _, ent := range ents {
		ede := et.NewEventDataElement(&et.Event{Name: ent.Asset.Key(), Entity: ent, Session: sess})
		ede.Exit = exit
		if err := ap.Queue.Append(ede); err != nil {
			t.Fatal(err)
		}
	}
	for range ents {
		<-exit
	}

	mu.Lock()
	defer mu.Unlock()
	slices.Sort(handled)
	return handled
}

func address(t *testing.T, sess *plugintest.Session, addr string) *dbt.Entity {
	return sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr(addr), Type: "IPv4"})
}

func prober(probes bool) *et.Handler {
	return &et.Handler{Plugin: &fakePlugin{"Prober"}, Name: "Prober-IPAddress",
		Transforms: []string{string(oam.Service)}, EventType: oam.IPAddress, Probes: probes}
}

// A transformation's reach keeps its handlers off assets outside the
// footprint; without a reach, the footprint policy applies.
func TestReachGatesHandlers(t *testing.T) {
	for _, tc := range []struct {
		reach string
		want  []string
	}{
		{config.ReachAny, []string{"192.0.2.1", "198.51.100.1"}},
		{"", []string{"192.0.2.1"}},
		{config.ReachFootprint, []string{"192.0.2.1"}},
	} {
		sess := plugintest.NewSession(t)
		sess.TTL(60)
		sess.Config().Transformations["ipaddress->all"].Reach = tc.reach
		sess.Scope().AddCIDR("192.0.2.0/24")

		got := gated(t, sess, prober(false), address(t, sess, "192.0.2.1"), address(t, sess, "198.51.100.1"))
		if !slices.Equal(got, tc.want) {
			t.Errorf("reach %q: handled %v, want %v", tc.reach, got, tc.want)
		}
	}
}

// Probes run only on addresses the scope takes in by themselves, whatever
// the reach: not on one that only an in-scope name resolves to, which may be
// a provider's shared host.
func TestProbesStayOnTheirOwnFootprint(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Config().Transformations["ipaddress->all"].Reach = config.ReachAny
	sess.Scope().AddDomain("example.com")
	sess.Scope().AddCIDR("192.0.2.0/24")

	own := address(t, sess, "192.0.2.1")
	hosting := address(t, sess, "198.51.100.1")
	www := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	sess.Edge(t, www, &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 1, Class: 1}}, hosting)
	other := address(t, sess, "203.0.113.1")

	if got := gated(t, sess, prober(true), own, hosting, other); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("probes ran on %v, want only the address in scope", got)
	}

	sess.Config().Transformations["ipaddress->all"].Reach = config.ReachFootprint
	if got := gated(t, sess, prober(false), own, hosting, other); !slices.Equal(got, []string{"192.0.2.1", "198.51.100.1"}) {
		t.Errorf("other handlers ran on %v, want the address in scope and the hosting of an in-scope name", got)
	}
}

// Identifying every organization (Organization->GLEIF: any) does not carry
// the collection that starts from an organization's identifiers to vendors:
// a vendor's LEI takes the vendor's standing.
func TestVendorIdentifiersStayOutOfTheFootprint(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Config().Transformations["organization->gleif"] = &config.Transformation{From: "organization",
		To: "gleif", Reach: config.ReachAny}

	target := sess.Asset(t, &oamorg.Organization{ID: "sunypoly:test", Name: "suny polytechnic institute"})
	vendor := sess.Asset(t, &oamorg.Organization{ID: "adobe:test", Name: "adobe"})
	sess.Scope().Add(target.Asset)

	var leis []*dbt.Entity
	for _, o := range []struct {
		org *dbt.Entity
		lei string
	}{{target, "LEI-TARGET"}, {vendor, "LEI-VENDOR"}} {
		lei := sess.Asset(t, &oamgen.Identifier{UniqueID: oamgen.LEICode + ":" + o.lei, ID: o.lei,
			Type: oamgen.LEICode})
		sess.Edge(t, o.org, &oamgen.SimpleRelation{Name: "id"}, lei)
		leis = append(leis, lei)
	}

	h := &et.Handler{Plugin: &fakePlugin{"GLEIF"}, Name: "GLEIF-Related",
		Transforms: []string{string(oam.Organization)}, EventType: oam.Identifier}
	if got := gated(t, sess, h, leis...); len(got) != 1 || got[0] != leis[0].Asset.Key() {
		t.Errorf("the corporate family was sought for %v, want only the target's LEI", got)
	}
}
