// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"context"
	"slices"
	"strconv"
	"sync"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// Bounds of the standing lookups, which read the database: the parents read
// per relation, the assets a connected check visits, and the assets held for
// reconsideration.
const (
	standingMaxParents   = 20
	connectedMaxEdges    = 50
	connectedMaxVisited  = 300
	standingMaxHeld      = 100000
	standingQueryTimeout = 10 * time.Second
)

// standings caches what the standing lookups found, valid until the scope
// grows, and holds the assets the gate kept from a handler, to reconsider
// when it does.
type standings struct {
	sync.Mutex
	version   uint64
	of        map[string]standingEntry
	connected map[string]standingEntry
	held      map[string]*dbt.Entity
}

type standingEntry struct {
	version  uint64
	standing et.Standing
	ok       bool
}

// scopeable reports whether the scope judges an asset by itself.
func scopeable(a oam.Asset) bool {
	switch v := a.(type) {
	case *oamgen.Identifier:
		return v.Type == oamgen.EmailAddress
	}
	switch a.AssetType() {
	case oam.FQDN, oam.IPAddress, oam.Netblock, oam.AutonomousSystem, oam.Organization, oam.StreetAddress,
		oam.Phone, oam.DomainRecord, oam.IPNetRecord, oam.AutnumRecord, oam.TLSCertificate, oam.URL:
		return true
	}
	return false
}

// StandingOf implements et.Admitter. An asset stands as Standing reports when
// the scope takes it in or a decision was made about it; otherwise it takes
// the best standing of the assets it hangs off (semantics standing.json). One
// the scope cannot judge, of a type with no rules there, is NotGoverned.
func (s *Scope) StandingOf(e *dbt.Entity) et.Standing {
	if e == nil || e.Asset == nil {
		return et.Unconsidered
	}
	ctx := context.Background()
	if s.Session != nil {
		ctx = s.Session.Ctx()
	}
	return s.standingOf(ctx, e, 0)
}

func (s *Scope) standingOf(ctx context.Context, e *dbt.Entity, depth int) et.Standing {
	rules := semantics.Standing()
	inherit := rules.Inherit[string(e.Asset.AssetType())]
	// matching, or an admission decision about the asset itself, first
	if st := s.Standing(e.Asset); st != et.Unconsidered || len(inherit) == 0 {
		if st == et.Unconsidered && !scopeable(e.Asset) {
			return et.NotGoverned
		}
		return st
	}

	s.st.Lock()
	version := s.st.version
	if c, ok := s.st.of[e.ID]; ok && c.version == version {
		s.st.Unlock()
		return c.standing
	}
	s.st.Unlock()

	best := et.Unconsidered
	if depth < rules.MaxDepth && s.Session != nil && s.Session.DB() != nil {
		qctx, cancel := context.WithTimeout(ctx, standingQueryTimeout)
		defer cancel()
		for _, rule := range inherit {
			for _, parent := range s.parents(qctx, e, rule.Labels, rule.From, rule.Outgoing) {
				if best == et.InScope {
					break
				}
				best = betterStanding(best, s.parentStanding(ctx, parent, rule, depth+1, rules.MaxDepth))
			}
		}
	}

	s.st.Lock()
	if s.st.of == nil {
		s.st.of = map[string]standingEntry{}
	}
	s.st.of[e.ID] = standingEntry{version: version, standing: best}
	s.st.Unlock()
	return best
}

// parentStanding is the standing an asset takes from a parent: the parent's
// own, or failing that, the best of the assets of the rule's types the parent
// hangs off through the rule's Through relations (an alias), up to maxDepth.
func (s *Scope) parentStanding(ctx context.Context, parent *dbt.Entity, rule semantics.StandingRule,
	depth, maxDepth int) et.Standing {
	st := s.standingOf(ctx, parent, depth)
	if InFootprint(st) || len(rule.Through) == 0 || depth >= maxDepth {
		return st
	}

	qctx, cancel := context.WithTimeout(ctx, standingQueryTimeout)
	defer cancel()
	for _, alias := range s.parents(qctx, parent, rule.Through, rule.From, false) {
		if st = betterStanding(st, s.parentStanding(ctx, alias, rule, depth+1, maxDepth)); st == et.InScope {
			break
		}
	}
	return st
}

// parents returns up to standingMaxParents assets of the types joined to e by
// relations with the labels: those relating to e, or with outgoing, those e
// relates to.
func (s *Scope) parents(ctx context.Context, e *dbt.Entity, labels, types []string, outgoing bool) []*dbt.Entity {
	var edges []*dbt.Edge
	var err error
	if outgoing {
		edges, err = s.Session.DB().OutgoingEdges(ctx, e, time.Time{}, labels...)
	} else {
		edges, err = s.Session.DB().IncomingEdges(ctx, e, time.Time{}, labels...)
	}
	if err != nil {
		return nil
	}

	var out []*dbt.Entity
	for i, edge := range edges {
		if i >= standingMaxParents {
			break
		}
		id := edge.FromEntity.ID
		if outgoing {
			id = edge.ToEntity.ID
		}
		p, err := s.Session.DB().FindEntityById(ctx, id)
		if err == nil && p != nil && p.Asset != nil && slices.Contains(types, string(p.Asset.AssetType())) {
			out = append(out, p)
		}
	}
	return out
}

// betterStanding returns the stronger of two standings.
func betterStanding(a, b et.Standing) et.Standing {
	rank := func(st et.Standing) int {
		switch st {
		case et.InScope:
			return 4
		case et.StandingAdmitted:
			return 3
		case et.StandingPending:
			return 2
		case et.StandingRejected:
			return 1
		}
		return 0
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// InFootprint reports whether a standing is in the footprint: in scope, or
// admitted into it.
func InFootprint(st et.Standing) bool {
	return st == et.InScope || st == et.StandingAdmitted
}

// ConnectedWithin implements et.Admitter: whether the asset is linked to the
// footprint within hops relations, either way. The walk reads at most
// connectedMaxEdges relations of an asset and visits at most
// connectedMaxVisited assets.
func (s *Scope) ConnectedWithin(e *dbt.Entity, hops int) bool {
	if e == nil || hops < 1 || s.Session == nil || s.Session.DB() == nil {
		return false
	}
	if InFootprint(s.StandingOf(e)) {
		return true
	}

	s.st.Lock()
	version := s.st.version
	key := e.ID + "|" + strconv.Itoa(hops)
	if c, ok := s.st.connected[key]; ok && c.version == version {
		s.st.Unlock()
		return c.ok
	}
	s.st.Unlock()

	ok := s.connected(e, hops)
	s.st.Lock()
	if s.st.connected == nil {
		s.st.connected = map[string]standingEntry{}
	}
	s.st.connected[key] = standingEntry{version: version, ok: ok}
	s.st.Unlock()
	return ok
}

func (s *Scope) connected(start *dbt.Entity, hops int) bool {
	ctx, cancel := context.WithTimeout(s.Session.Ctx(), standingQueryTimeout)
	defer cancel()

	visited := map[string]bool{start.ID: true}
	frontier := []*dbt.Entity{start}
	for depth := 0; depth < hops && len(frontier) > 0; depth++ {
		var next []*dbt.Entity
		for _, cur := range frontier {
			out, _ := s.Session.DB().OutgoingEdges(ctx, cur, time.Time{})
			in, _ := s.Session.DB().IncomingEdges(ctx, cur, time.Time{})
			for i, edge := range append(out[:min(len(out), connectedMaxEdges)], in[:min(len(in), connectedMaxEdges)]...) {
				id := edge.ToEntity.ID
				if i >= min(len(out), connectedMaxEdges) {
					id = edge.FromEntity.ID
				}
				if visited[id] || len(visited) >= connectedMaxVisited {
					continue
				}
				visited[id] = true
				n, err := s.Session.DB().FindEntityById(ctx, id)
				if err != nil || n == nil || n.Asset == nil {
					continue
				}
				if InFootprint(s.standingOf(ctx, n, 0)) {
					return true
				}
				next = append(next, n)
			}
		}
		frontier = next
	}
	return false
}

// Hold implements et.Admitter: the gate kept a handler from the asset, so it
// is queued again once the scope grows to take it in.
func (s *Scope) Hold(e *dbt.Entity) {
	if e == nil {
		return
	}
	s.st.Lock()
	defer s.st.Unlock()
	if s.st.held == nil {
		s.st.held = map[string]*dbt.Entity{}
	}
	if len(s.st.held) < standingMaxHeld {
		s.st.held[e.ID] = e
	}
}

// grown marks the scope as grown, so cached standings are judged again, and
// queues each held asset that the scope now takes in.
func (s *Scope) grown() {
	s.st.Lock()
	s.st.version++
	held := make([]*dbt.Entity, 0, len(s.st.held))
	for _, e := range s.st.held {
		held = append(held, e)
	}
	s.st.Unlock()
	if len(held) == 0 || s.Session == nil || s.Session.Backlog() == nil {
		return
	}

	for _, e := range held {
		if !InFootprint(s.StandingOf(e)) {
			continue
		}
		s.st.Lock()
		delete(s.st.held, e.ID)
		s.st.Unlock()
		_ = s.Session.Backlog().Enqueue(e)
	}
}
