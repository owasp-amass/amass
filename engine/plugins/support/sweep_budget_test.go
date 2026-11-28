// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// fakeSweepDB stores every address, links each its reverse DNS alias, and
// gives the addresses in forward a forward DNS name.
type fakeSweepDB struct{ forward map[string]bool }

func (f *fakeSweepDB) FindEntitiesByContent(_ context.Context, _ oam.AssetType, _ time.Time, _ int,
	filters dbt.ContentFilters) ([]*dbt.Entity, error) {
	s, _ := filters["address"].(string)
	return []*dbt.Entity{{ID: s}}, nil
}

func (f *fakeSweepDB) IncomingEdges(_ context.Context, entity *dbt.Entity, _ time.Time,
	_ ...string) ([]*dbt.Edge, error) {
	if f.forward[entity.ID] {
		return []*dbt.Edge{{Relation: &oamgen.SimpleRelation{Name: "dns_record"}}}, nil
	}
	return nil, nil
}

func (f *fakeSweepDB) OutgoingEdges(context.Context, *dbt.Entity, time.Time, ...string) ([]*dbt.Edge, error) {
	return []*dbt.Edge{{Relation: &oamgen.SimpleRelation{Name: "ptr_record"}}}, nil
}

func TestSweepBudgetSpend(t *testing.T) {
	b := SweepBudgetFor(plugintest.NewSession(t))

	const cidr = "198.51.100.0/24"
	// Unseeded netblock grants nothing.
	if got := b.TrySpend(cidr, 10); got != 0 {
		t.Fatalf("unseeded TrySpend = %d, want 0", got)
	}

	b.Seed(cidr, 64)
	// Seeding again must not reset an already-tracked netblock.
	b.Seed(cidr, 1000)

	if got := b.TrySpend(cidr, 50); got != 50 {
		t.Fatalf("TrySpend(50) = %d, want 50", got)
	}
	if got := b.TrySpend(cidr, 50); got != 14 {
		t.Fatalf("TrySpend(50) with 14 left = %d, want 14 (clamped to remaining)", got)
	}
	if got := b.TrySpend(cidr, 50); got != 0 {
		t.Fatalf("TrySpend on exhausted budget = %d, want 0", got)
	}
	if got := b.TrySpend(cidr, 0); got != 0 {
		t.Fatalf("TrySpend(0) = %d, want 0", got)
	}
}

// Addresses a forward DNS name resolves to refund the budget once each; one
// that only answers reverse DNS refunds nothing, and is dead once it had
// the settle time to show a hit.
func TestSweepBudgetRefund(t *testing.T) {
	b := SweepBudgetFor(plugintest.NewSession(t))

	const cidr = "198.51.100.0/24"
	b.Seed(cidr, 64)
	if got := b.TrySpend(cidr, 64); got != 64 {
		t.Fatalf("TrySpend(64) = %d, want 64", got)
	}

	b.RecordSwept(cidr, "198.51.100.1")
	b.RecordSwept(cidr, "198.51.100.2")
	b.RecordSwept(cidr, "198.51.100.3")
	// An address outside any tracked netblock is ignored.
	b.RecordSwept("203.0.113.0/24", "203.0.113.1")

	db := &fakeSweepDB{forward: map[string]bool{"198.51.100.1": true, "198.51.100.3": true}}
	now := time.Now()
	if !b.recheck(context.Background(), db, cidr, now) {
		t.Fatal("two hits refunded nothing")
	}
	if got := b.TrySpend(cidr, 1_000); got != 2*sweepRefundPerHit {
		t.Fatalf("after 2 hits TrySpend = %d, want %d", got, 2*sweepRefundPerHit)
	}

	// Checks come at most once per sweepRecheckEvery, never credit a hit
	// twice, and settle the reverse-DNS-only address as dead.
	if b.recheck(context.Background(), db, cidr, now.Add(time.Second)) {
		t.Error("a recheck ran again before sweepRecheckEvery")
	}
	if b.recheck(context.Background(), db, cidr, now.Add(sweepSettle)) {
		t.Error("the same hits were credited twice")
	}
	if n := len(b.nb[cidr].pending); n != 0 {
		t.Errorf("%d addresses still pending after the settle time", n)
	}
}

func TestSweepBudgetCaps(t *testing.T) {
	b := SweepBudgetFor(plugintest.NewSession(t))

	const cidr = "198.51.100.0/24"
	b.Seed(cidr, 10)
	_ = b.TrySpend(cidr, 10)

	forward := map[string]bool{}
	for i := 0; i < 200; i++ {
		addr := fmt.Sprintf("198.51.100.%d", i)
		b.RecordSwept(cidr, addr)
		forward[addr] = true
	}
	b.recheck(context.Background(), &fakeSweepDB{forward: forward}, cidr, time.Now())
	if got := b.TrySpend(cidr, 1_000_000); got != sweepBudgetCeiling-10 {
		t.Fatalf("TrySpend = %d, want the ceiling less what was swept, %d", got, sweepBudgetCeiling-10)
	}

	// however much is refunded, a netblock is swept for at most
	// sweepNetblockMax addresses
	b.nb[cidr].remaining = sweepBudgetCeiling
	if got := b.TrySpend(cidr, 1_000_000); got != 0 {
		t.Errorf("TrySpend past sweepNetblockMax = %d, want 0", got)
	}
}

// A sweep in a netblock the scope holds spends its budget; elsewhere it
// sweeps what was asked.
func TestBudgetedSweep(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.Scope().AddCIDR("198.51.100.0/24")
	sess.Scope().AddCIDR("198.51.100.0/25")

	if cidr, ok := ScopeNetblock(sess, netip.MustParseAddr("198.51.100.10")); !ok || cidr != "198.51.100.0/25" {
		t.Errorf("ScopeNetblock = %q, %v, want the most specific netblock", cidr, ok)
	}

	sweep := func(addr string, size int) int {
		n := 0
		e := &et.Event{Session: sess}
		ip := &oamnet.IPAddress{Address: netip.MustParseAddr(addr), Type: "IPv4"}
		BudgetedSweep(e, ip, &et.Source{Name: "test"}, size, func(*et.Event, *oamnet.IPAddress, *et.Source) { n++ })
		return n
	}

	if n := sweep("198.51.100.10", 100); n > SweepSeedWindow+1 {
		t.Errorf("the first sweep in the netblock covered %d addresses, want at most its budget", n)
	}
	if n := sweep("198.51.100.20", 100); n != 0 {
		t.Errorf("a sweep with the budget spent and no hits covered %d addresses", n)
	}
	if n := sweep("203.0.113.10", 20); n < 20 {
		t.Errorf("a sweep outside the scope's netblocks covered %d addresses, want 20", n)
	}
}
