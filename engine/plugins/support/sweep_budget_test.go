// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
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

func (f *fakeSweepDB) FindEntityById(context.Context, string) (*dbt.Entity, error) {
	return nil, errors.New("not found")
}

func (f *fakeSweepDB) FindEntityTags(context.Context, *dbt.Entity, time.Time, ...string) ([]*dbt.EntityTag, error) {
	return nil, nil
}

func (f *fakeSweepDB) DeleteEntity(context.Context, string) error { return nil }

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
	if !b.recheck(context.Background(), db, cidr, time.Time{}, now) {
		t.Fatal("two hits refunded nothing")
	}
	if got := b.TrySpend(cidr, 1_000); got != 2*sweepRefundPerHit {
		t.Fatalf("after 2 hits TrySpend = %d, want %d", got, 2*sweepRefundPerHit)
	}

	// Checks come at most once per sweepRecheckEvery, never credit a hit
	// twice, and settle the reverse-DNS-only address as dead.
	if b.recheck(context.Background(), db, cidr, time.Time{}, now.Add(time.Second)) {
		t.Error("a recheck ran again before sweepRecheckEvery")
	}
	if b.recheck(context.Background(), db, cidr, time.Time{}, now.Add(sweepSettle)) {
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
	b.recheck(context.Background(), &fakeSweepDB{forward: forward}, cidr, time.Time{}, time.Now())
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

// A dead address the session stored, with its unanswered reverse DNS alias,
// is removed; one with a PTR answer, or stored before the session, is kept.
func TestPruneDead(t *testing.T) {
	sess := plugintest.NewSession(t)
	ctx := context.Background()
	since := time.Now().Add(-time.Minute)
	later := time.Now().Add(sweepPruneQuiet + time.Minute)

	nb := sess.Asset(t, &oamnet.Netblock{CIDR: netip.MustParsePrefix("198.51.100.0/24"), Type: "IPv4"})
	swept := func(last string) (*dbt.Entity, *dbt.Entity) {
		ip := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("198.51.100." + last), Type: "IPv4"})
		alias := sess.Asset(t, &oamdns.FQDN{Name: last + ".100.51.198.in-addr.arpa"})
		sess.Edge(t, nb, &oamgen.SimpleRelation{Name: "contains"}, ip)
		sess.Edge(t, ip, &oamgen.SimpleRelation{Name: "ptr_record"}, alias)
		return ip, alias
	}

	dead, deadAlias := swept("7")
	if pruneDead(ctx, sess.DB(), "198.51.100.7", time.Now().Add(time.Hour), later) {
		t.Error("an address stored before the session was removed")
	}
	if !pruneDead(ctx, sess.DB(), "198.51.100.7", since, later) {
		t.Fatal("the dead address was kept")
	}
	for _, id := range []string{dead.ID, deadAlias.ID} {
		if _, err := sess.DB().FindEntityById(ctx, id); err == nil {
			t.Errorf("%s is still stored", id)
		}
	}
	if _, err := sess.DB().FindEntityById(ctx, nb.ID); err != nil {
		t.Error("the netblock was removed")
	}

	_, answered := swept("8")
	host := sess.Asset(t, &oamdns.FQDN{Name: "host.owasp.org"})
	sess.Edge(t, answered, &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 12}}, host)
	if pruneDead(ctx, sess.DB(), "198.51.100.8", since, later) {
		t.Error("an address with a PTR answer was removed")
	}
}

// Once the session's other work is done, every swept address that showed
// no hit is removed whatever its age, and is not swept again.
func TestSweepBudgetFinish(t *testing.T) {
	sess := plugintest.NewSession(t)
	ctx := context.Background()
	b := SweepBudgetFor(sess)

	const cidr = "198.51.100.0/24"
	b.Seed(cidr, 64)
	nb := sess.Asset(t, &oamnet.Netblock{CIDR: netip.MustParsePrefix(cidr), Type: "IPv4"})
	ip := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("198.51.100.9"), Type: "IPv4"})
	sess.Edge(t, nb, &oamgen.SimpleRelation{Name: "contains"}, ip)
	b.RecordSwept(cidr, "198.51.100.9")

	if !SessionDrained(sess.Stats()) {
		t.Fatal("a session with no work is not drained")
	}
	b.finish(ctx, sess.DB(), time.Now().Add(-time.Minute), time.Now())
	if _, err := sess.DB().FindEntityById(ctx, ip.ID); err == nil {
		t.Error("the dead address swept just now was kept at the end of the session")
	}
	if !b.removed(cidr, "198.51.100.9") {
		t.Error("the removed address may be swept again")
	}
}
