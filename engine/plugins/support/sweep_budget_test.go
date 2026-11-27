// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// fakeSweepDB confirms exactly the addresses in its set: a confirmed address
// has a stored IPAddress with an outgoing edge, an unconfirmed one does not.
type fakeSweepDB struct{ confirmed map[string]bool }

func (f *fakeSweepDB) FindEntitiesByContent(_ context.Context, _ oam.AssetType, _ time.Time, _ int, filters dbt.ContentFilters) ([]*dbt.Entity, error) {
	s, _ := filters["address"].(string)
	if f.confirmed[s] {
		return []*dbt.Entity{{ID: s}}, nil
	}
	return nil, nil
}

func (f *fakeSweepDB) OutgoingEdges(_ context.Context, entity *dbt.Entity, _ time.Time, _ ...string) ([]*dbt.Edge, error) {
	if entity != nil && f.confirmed[entity.ID] {
		return []*dbt.Edge{{}}, nil
	}
	return nil, nil
}

func TestSweepBudgetSpend(t *testing.T) {
	const sid = "test-sweep-spend"
	defer DiscardSweepBudget(sid)
	b := SweepBudgetFor(sid)

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

func TestSweepBudgetRefund(t *testing.T) {
	const sid = "test-sweep-refund"
	defer DiscardSweepBudget(sid)
	b := SweepBudgetFor(sid)

	const cidr = "198.51.100.0/24"
	b.Seed(cidr, 64)
	if got := b.TrySpend(cidr, 64); got != 64 {
		t.Fatalf("TrySpend(64) = %d, want 64", got)
	}

	b.RecordSwept(cidr, "198.51.100.1")
	b.RecordSwept(cidr, "198.51.100.2")
	b.RecordSwept(cidr, "198.51.100.3")
	// An address outside any tracked netblock is ignored.
	b.RecordSwept("10.0.0.0/8", "10.0.0.1")

	db := &fakeSweepDB{confirmed: map[string]bool{"198.51.100.1": true, "198.51.100.3": true}}
	RecheckSweepBudgets(context.Background(), db, sid)

	// Two confirmed hits refund two windows.
	if got := b.TrySpend(cidr, 1_000); got != 2*sweepRefundPerHit {
		t.Fatalf("after 2 hits TrySpend = %d, want %d", got, 2*sweepRefundPerHit)
	}

	// A second re-check must not re-credit the same hits.
	RecheckSweepBudgets(context.Background(), db, sid)
	if got := b.TrySpend(cidr, 1_000); got != 0 {
		t.Fatalf("second re-check re-credited hits: TrySpend = %d, want 0", got)
	}
}

func TestSweepBudgetRefundCeiling(t *testing.T) {
	const sid = "test-sweep-ceiling"
	defer DiscardSweepBudget(sid)
	b := SweepBudgetFor(sid)

	const cidr = "198.51.100.0/24"
	b.Seed(cidr, 10)
	_ = b.TrySpend(cidr, 10)

	confirmed := make(map[string]bool)
	for i := 0; i < 200; i++ {
		addr := "150.156.2." + itoa(i)
		b.RecordSwept(cidr, addr)
		confirmed[addr] = true
	}
	RecheckSweepBudgets(context.Background(), &fakeSweepDB{confirmed: confirmed}, sid)

	if got := b.TrySpend(cidr, 1_000_000); got != sweepBudgetCeiling {
		t.Fatalf("refund not capped: TrySpend = %d, want ceiling %d", got, sweepBudgetCeiling)
	}
}

// itoa avoids a strconv import for the 0-199 test addresses.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
