// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"net/netip"
	"sync"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// The neighborhood sweep (IPAddressSweep) probes addresses around a located
// host. In a netblock the scope holds, every address is fair game, so the
// sweeps there could add up to the whole network: a /16 is 65,536 addresses,
// and some networks answer reverse DNS for every one of them. The sweep
// budget bounds how much of a netblock in scope one session sweeps, and
// refunds it as evidence accrues: a swept address that turns out to host
// something (a forward DNS name, a service) earns more exploration, so
// dense space keeps expanding while dead space drains the budget and stops.
// An address that answers only reverse DNS earns nothing.
//
// The budget is per session and per netblock and lives only in memory for
// the life of the enumeration. It is operational throttling of the sweep,
// not a review artifact.
const (
	// SweepSeedWindow is the budget a netblock starts with: one sweep
	// window, enough to probe the neighborhood of the first located host.
	SweepSeedWindow = 64
	// sweepRefundPerHit is the budget returned for each swept address later
	// confirmed to host a real asset.
	sweepRefundPerHit = 64
	// sweepBudgetCeiling caps a netblock's outstanding budget.
	sweepBudgetCeiling = 4096
	// sweepNetblockMax caps how many addresses of one netblock a session
	// sweeps in all, however many hits refund its budget.
	sweepNetblockMax = 4096
	// sweepRecheckEvery is how often a netblock whose budget runs short
	// checks its swept addresses for hits.
	sweepRecheckEvery = 30 * time.Second
	// sweepSettle is how long a swept address has to show a hit; after it,
	// one without a hit is dead and is not checked again.
	sweepSettle = 2 * time.Minute
)

// SweepDB is the read access the budget's refunds need; asset-db
// repositories (what Session.DB() returns) satisfy it.
type SweepDB interface {
	FindEntitiesByContent(ctx context.Context, atype oam.AssetType, since time.Time, limit int, filters dbt.ContentFilters) ([]*dbt.Entity, error)
	IncomingEdges(ctx context.Context, entity *dbt.Entity, since time.Time, labels ...string) ([]*dbt.Edge, error)
	OutgoingEdges(ctx context.Context, entity *dbt.Entity, since time.Time, labels ...string) ([]*dbt.Edge, error)
}

type nbBudget struct {
	remaining int
	// granted is how many addresses the netblock has been swept for.
	granted int
	checked time.Time
	// pending are the swept addresses not yet confirmed or found dead, with
	// when each was swept; done are those that were.
	pending map[string]time.Time
	done    map[string]bool
}

// SweepBudget holds one session's per-netblock sweep budgets.
type SweepBudget struct {
	mu   sync.Mutex
	sess et.Session
	nb   map[string]*nbBudget
}

// sweepBudgets holds every live session's budget, keyed by session ID string.
var sweepBudgets sync.Map

// SweepBudgetFor returns the sweep budget for a session, creating it on first
// use; budgets of sessions that are done are dropped then.
func SweepBudgetFor(sess et.Session) *SweepBudget {
	id := sess.ID().String()
	if v, ok := sweepBudgets.Load(id); ok {
		return v.(*SweepBudget)
	}

	sweepBudgets.Range(func(k, v any) bool {
		if s := v.(*SweepBudget).sess; s != nil && s.Done() {
			sweepBudgets.Delete(k)
		}
		return true
	})

	b := &SweepBudget{sess: sess, nb: make(map[string]*nbBudget)}
	actual, _ := sweepBudgets.LoadOrStore(id, b)
	return actual.(*SweepBudget)
}

// Seed gives a netblock its starting budget the first time it is swept; a
// netblock already tracked keeps the budget it has earned.
func (b *SweepBudget) Seed(cidr string, window int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.nb[cidr]; !ok {
		b.nb[cidr] = &nbBudget{remaining: window, pending: map[string]time.Time{}, done: map[string]bool{}}
	}
}

// TrySpend grants up to want addresses from the netblock's budget and debits
// them, returning how many may be swept now: 0 when the netblock has no
// budget left, has been swept for sweepNetblockMax addresses, or was never
// seeded.
func (b *SweepBudget) TrySpend(cidr string, want int) int {
	if want <= 0 {
		return 0
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	e, ok := b.nb[cidr]
	if !ok {
		return 0
	}

	grant := min(want, e.remaining, sweepNetblockMax-e.granted)
	if grant <= 0 {
		return 0
	}

	e.remaining -= grant
	e.granted += grant
	return grant
}

// RecordSwept notes that addr was swept within cidr, pending a check of
// whether it hosts a real asset. Addresses outside a tracked netblock, and
// ones already recorded, are ignored.
func (b *SweepBudget) RecordSwept(cidr, addr string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e, ok := b.nb[cidr]; ok && !e.done[addr] {
		if _, seen := e.pending[addr]; !seen {
			e.pending[addr] = time.Now()
		}
	}
}

// recheck refunds the netblock's budget by how many of its pending swept
// addresses have turned out to host a real asset, at most once per
// sweepRecheckEvery. A pending address that has had sweepSettle to show a
// hit and has none is dead. It reports whether it refunded anything.
func (b *SweepBudget) recheck(ctx context.Context, db SweepDB, cidr string, now time.Time) bool {
	b.mu.Lock()
	e, ok := b.nb[cidr]
	if !ok || db == nil || now.Sub(e.checked) < sweepRecheckEvery {
		b.mu.Unlock()
		return false
	}

	e.checked = now
	pending := make(map[string]time.Time, len(e.pending))
	for addr, at := range e.pending {
		pending[addr] = at
	}
	b.mu.Unlock()

	hits := 0
	var settled []string
	for addr, at := range pending {
		if ctx.Err() != nil {
			break
		}
		if sweepAddrConfirmed(ctx, db, addr) {
			hits++
			settled = append(settled, addr)
		} else if now.Sub(at) >= sweepSettle {
			settled = append(settled, addr)
		}
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	for _, addr := range settled {
		delete(e.pending, addr)
		e.done[addr] = true
	}
	if hits > 0 {
		e.remaining = min(e.remaining+hits*sweepRefundPerHit, sweepBudgetCeiling)
	}
	return hits > 0
}

// sweepAddrConfirmed reports whether a swept address hosts a real asset: a
// forward DNS name resolves to it, or it has a relation other than its
// reverse DNS record, such as a probed service. A swept address is stored
// either way, and its reverse DNS alias is linked before the query is
// answered, so neither counts.
func sweepAddrConfirmed(ctx context.Context, db SweepDB, addr string) bool {
	ents, err := db.FindEntitiesByContent(ctx, oam.IPAddress, time.Time{}, 1, dbt.ContentFilters{"address": addr})
	if err != nil || len(ents) == 0 {
		return false
	}

	if in, _ := db.IncomingEdges(ctx, ents[0], time.Time{}, "dns_record"); len(in) > 0 {
		return true
	}

	out, _ := db.OutgoingEdges(ctx, ents[0], time.Time{})
	for _, edge := range out {
		if edge.Relation == nil || edge.Relation.Label() != "ptr_record" {
			return true
		}
	}
	return false
}

// ScopeNetblock returns the most specific netblock in the session's scope
// that holds addr.
func ScopeNetblock(sess et.Session, addr netip.Addr) (string, bool) {
	var best *oamnet.Netblock
	for _, nb := range sess.Scope().Netblocks() {
		if nb != nil && nb.CIDR.Contains(addr) && (best == nil || nb.CIDR.Bits() > best.CIDR.Bits()) {
			best = nb
		}
	}
	if best == nil {
		return "", false
	}
	return best.CIDR.String(), true
}

// BudgetedSweep sweeps size addresses around addr (IPAddressSweep). When
// addr is in a netblock the scope holds, the sweep spends that netblock's
// budget instead: it sweeps only what the budget grants and records what it
// swept for the refunds, so the sweeps around many hosts in one network
// never add up to the whole network.
func BudgetedSweep(e *et.Event, addr *oamnet.IPAddress, src *et.Source, size int, callback SweepCallback) {
	cidr, ok := ScopeNetblock(e.Session, addr.Address)
	if !ok {
		IPAddressSweep(e, addr, src, size, callback)
		return
	}

	b := SweepBudgetFor(e.Session)
	b.Seed(cidr, SweepSeedWindow)
	granted := b.TrySpend(cidr, size)
	if granted < size {
		ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
		if b.recheck(ctx, e.Session.DB(), cidr, time.Now()) {
			granted += b.TrySpend(cidr, size-granted)
		}
		cancel()
	}
	if granted <= 0 {
		return
	}

	IPAddressSweep(e, addr, src, granted, func(ev *et.Event, a *oamnet.IPAddress, s *et.Source) {
		b.RecordSwept(cidr, a.Address.String())
		callback(ev, a, s)
	})
}
