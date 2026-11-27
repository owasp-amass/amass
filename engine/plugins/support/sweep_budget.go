// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"sync"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// The active-enumeration neighborhood sweep (IPAddressSweep) probes addresses
// around a located host. In a netblock the organization owns, every address is
// fair game, so the sweep is allowed to widen — but a large owned network (a
// /16 is 65,536 addresses) must not be probed wholesale on the strength of
// ownership alone. The sweep budget bounds how much of an owned netblock is
// swept speculatively, and refunds that budget as evidence accrues: each swept
// address that turns out to host a real asset earns more exploration, so dense
// owned space keeps expanding while dead space drains the budget and stops.
//
// The budget is per session and per netblock, lives only in memory for the
// life of the enumeration, and is not a review artifact — it is operational
// throttling of the sweep, which is why it sits beside IPAddressSweep rather
// than in the review package.
const (
	// SweepSeedWindow is the budget a newly owned netblock starts with: one
	// sweep window, enough to probe the neighborhood of the first located host.
	SweepSeedWindow = 64
	// sweepRefundPerHit is the budget returned for each swept address later
	// confirmed to host a real asset.
	sweepRefundPerHit = 64
	// sweepBudgetCeiling caps a netblock's outstanding budget so refunds can
	// never let one network's sweep grow without bound.
	sweepBudgetCeiling = 4096
)

// SweepDB is the read access the budget top-up needs; *asset-db* repositories
// (what Session.DB() returns) satisfy it.
type SweepDB interface {
	FindEntitiesByContent(ctx context.Context, atype oam.AssetType, since time.Time, limit int, filters dbt.ContentFilters) ([]*dbt.Entity, error)
	OutgoingEdges(ctx context.Context, entity *dbt.Entity, since time.Time, labels ...string) ([]*dbt.Edge, error)
}

type nbBudget struct {
	remaining int
	// swept maps each swept address to whether it has already been credited as
	// a confirmed hit, so a hit refunds the budget exactly once.
	swept map[string]bool
}

// SweepBudget holds one session's per-netblock sweep budgets.
type SweepBudget struct {
	mu sync.Mutex
	nb map[string]*nbBudget
}

// sweepBudgets holds every live session's budget, keyed by session ID string.
var sweepBudgets sync.Map

// SweepBudgetFor returns the sweep budget for a session, creating it on first
// use. The session ID (uuid string) is the key.
func SweepBudgetFor(sessionID string) *SweepBudget {
	if v, ok := sweepBudgets.Load(sessionID); ok {
		return v.(*SweepBudget)
	}
	b := &SweepBudget{nb: make(map[string]*nbBudget)}
	actual, _ := sweepBudgets.LoadOrStore(sessionID, b)
	return actual.(*SweepBudget)
}

// DiscardSweepBudget drops a session's budget once its enumeration is over.
func DiscardSweepBudget(sessionID string) {
	sweepBudgets.Delete(sessionID)
}

// Seed gives an owned netblock its starting budget the first time it is added
// to scope; a netblock already tracked keeps the budget it has earned.
func (b *SweepBudget) Seed(cidr string, window int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.nb[cidr]; !ok {
		b.nb[cidr] = &nbBudget{remaining: window, swept: make(map[string]bool)}
	}
}

// TrySpend grants up to want addresses from the netblock's budget and debits
// them, returning how many may be swept now (0 when the netblock has no budget
// left or was never seeded).
func (b *SweepBudget) TrySpend(cidr string, want int) int {
	if want <= 0 {
		return 0
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	e, ok := b.nb[cidr]
	if !ok || e.remaining <= 0 {
		return 0
	}
	grant := want
	if grant > e.remaining {
		grant = e.remaining
	}
	e.remaining -= grant
	return grant
}

// RecordSwept notes that addr was swept within cidr, pending a later check of
// whether it hosts a real asset. Addresses outside a tracked netblock, and
// ones already recorded, are ignored.
func (b *SweepBudget) RecordSwept(cidr, addr string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e, ok := b.nb[cidr]; ok {
		if _, seen := e.swept[addr]; !seen {
			e.swept[addr] = false
		}
	}
}

// refund credits the netblock for newly confirmed hits, capped at the ceiling.
func (b *SweepBudget) refund(cidr string, hits int) {
	if hits <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if e, ok := b.nb[cidr]; ok {
		e.remaining += hits * sweepRefundPerHit
		if e.remaining > sweepBudgetCeiling {
			e.remaining = sweepBudgetCeiling
		}
	}
}

// pendingSwept returns, per netblock, the swept addresses not yet credited as
// hits, as a snapshot so the DB reads below run without holding the lock.
func (b *SweepBudget) pendingSwept() map[string][]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string][]string)
	for cidr, e := range b.nb {
		var pending []string
		for addr, credited := range e.swept {
			if !credited {
				pending = append(pending, addr)
			}
		}
		if len(pending) > 0 {
			out[cidr] = pending
		}
	}
	return out
}

// markCredited records that addr in cidr has been counted as a hit.
func (b *SweepBudget) markCredited(cidr, addr string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e, ok := b.nb[cidr]; ok {
		e.swept[addr] = true
	}
}

// RecheckSweepBudgets refunds each netblock's sweep budget by how many of its
// swept addresses have since turned out to host a real asset. It is meant to
// run on the attribution re-check drain, where the enumeration's discoveries
// have settled, so that budget keeps flowing to networks that are paying off.
func RecheckSweepBudgets(ctx context.Context, db SweepDB, sessionID string) {
	if db == nil {
		return
	}
	b := SweepBudgetFor(sessionID)

	for cidr, addrs := range b.pendingSwept() {
		hits := 0
		for _, addr := range addrs {
			if ctx.Err() != nil {
				return
			}
			if sweepAddrConfirmed(ctx, db, addr) {
				hits++
				b.markCredited(cidr, addr)
			}
		}
		b.refund(cidr, hits)
	}
}

// sweepAddrConfirmed reports whether a swept address hosts a real asset: a
// stored IPAddress with at least one outgoing edge. A dead sweep target is
// created without edges, while a PTR record, a probed service or a certificate
// discovered at the address all attach an edge, so any outgoing edge is
// evidence the neighborhood is worth exploring.
func sweepAddrConfirmed(ctx context.Context, db SweepDB, addr string) bool {
	ents, err := db.FindEntitiesByContent(ctx, oam.IPAddress, time.Time{}, 1, dbt.ContentFilters{"address": addr})
	if err != nil || len(ents) == 0 {
		return false
	}
	edges, err := db.OutgoingEdges(ctx, ents[0], time.Time{})
	return err == nil && len(edges) > 0
}
