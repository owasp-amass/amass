// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/sessions"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// writeCounter counts the writes plugin code makes.
type writeCounter struct {
	repository.Repository
	writes atomic.Int64
}

func (w *writeCounter) CreateAsset(ctx context.Context, a oam.Asset) (*dbt.Entity, error) {
	w.writes.Add(1)
	return w.Repository.CreateAsset(ctx, a)
}

func (w *writeCounter) CreateEdge(ctx context.Context, e *dbt.Edge) (*dbt.Edge, error) {
	w.writes.Add(1)
	return w.Repository.CreateEdge(ctx, e)
}

func (w *writeCounter) CreateEntityProperty(ctx context.Context, e *dbt.Entity,
	p oam.Property) (*dbt.EntityTag, error) {
	w.writes.Add(1)
	return w.Repository.CreateEntityProperty(ctx, e, p)
}

func (w *writeCounter) CreateEdgeProperty(ctx context.Context, e *dbt.Edge, p oam.Property) (*dbt.EdgeTag, error) {
	w.writes.Add(1)
	return w.Repository.CreateEdgeProperty(ctx, e, p)
}

type nopDispatcher struct {
	et.Dispatcher
	events atomic.Int64
}

func (d *nopDispatcher) DispatchEvent(*et.Event) error {
	d.events.Add(1)
	return nil
}

// Every address of a netblock gets its own contains relation, but the
// netblock, its AS and the announces relation are stored and sent on once
// per session.
func TestIPNetblockStoresTheNetblockOncePerSession(t *testing.T) {
	sess := plugintest.NewSession(t)
	counter := &writeCounter{}
	sess.WrapDB(func(r repository.Repository) repository.Repository {
		counter.Repository = r
		return counter
	})

	d := NewIPNetblock().(*ipNetblock)
	_, ipnet, _ := net.ParseCIDR("192.0.2.0/24")
	entry := &sessions.CIDRangerEntry{Net: ipnet, ASN: 64500, Src: &et.Source{Name: "RIR", Confidence: 90}}
	disp := &nopDispatcher{}

	const addrs = 20
	var ips []*dbt.Entity
	for i := range addrs {
		ip := sess.Asset(t, &oamnet.IPAddress{Address: netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), Type: "IPv4"})
		ips = append(ips, ip)
	}

	counter.writes.Store(0)
	for _, ip := range ips {
		e := &et.Event{Entity: ip, Session: sess, Dispatcher: disp}
		nb, as, _ := d.store(e, entry)
		if nb == nil || as == nil {
			t.Fatal("the netblock was not stored")
		}

		d.process(e, ip, nb, as, false)
	}

	// The first address: netblock, AS, announces and their three sources,
	// plus its contains relation and source (8); the others: 2 each.
	if got, want := counter.writes.Load(), int64(8+2*(addrs-1)); got != want {
		t.Errorf("%d writes for %d addresses, want %d", got, addrs, want)
	}

	ctx := context.Background()
	nbs, err := sess.DB().FindEntitiesByContent(ctx, oam.Netblock, time.Time{}, 0,
		dbt.ContentFilters{"cidr": "192.0.2.0/24"})
	if err != nil || len(nbs) != 1 {
		t.Fatalf("netblock: %v, %v", nbs, err)
	}

	contains, err := sess.DB().OutgoingEdges(ctx, nbs[0], time.Time{}, "contains")
	if err != nil || len(contains) != addrs {
		t.Errorf("the netblock contains %d addresses, want %d: %v", len(contains), addrs, err)
	}

	as, err := sess.DB().FindEntitiesByContent(ctx, oam.AutonomousSystem, time.Time{}, 0,
		dbt.ContentFilters{"number": 64500})
	if err != nil || len(as) != 1 {
		t.Fatalf("autonomous system: %v, %v", as, err)
	}
	if announces, err := sess.DB().OutgoingEdges(ctx, as[0], time.Time{}, "announces"); err != nil ||
		len(announces) != 1 {
		t.Errorf("announces: %v, %v", announces, err)
	}

	// Another session (perhaps another database) stores its own.
	other := plugintest.NewSession(t)
	ip := other.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.200"), Type: "IPv4"})
	if nb, as, first := d.store(&et.Event{Entity: ip, Session: other}, entry); nb == nil || as == nil || !first {
		t.Error("another session reused this session's netblock")
	}
}

// The netblock and AS events are sent on only the first time.
func TestIPNetblockProcessSendsTheNetblockOnce(t *testing.T) {
	sess := plugintest.NewSession(t)
	d := NewIPNetblock().(*ipNetblock)
	disp := &nopDispatcher{}

	ip := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.1"), Type: "IPv4"})
	nb := sess.Asset(t, &oamnet.Netblock{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Type: "IPv4"})
	as := sess.Asset(t, &oamnet.AutonomousSystem{Number: 64500})
	e := &et.Event{Entity: ip, Session: sess, Dispatcher: disp}

	d.process(e, ip, nb, as, true)
	d.process(e, ip, nb, as, false)
	if n := disp.events.Load(); n != 2 {
		t.Errorf("%d events sent on, want the netblock and AS once", n)
	}
}
