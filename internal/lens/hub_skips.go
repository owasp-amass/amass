// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// HubSkip is a shared value a signal passed over because more assets hold
// it than the hub limit allows: a provider's, registrar's or platform's
// value, not one owner's. Results list these so a reviewer can see why a
// value that looks like evidence did not count.
type HubSkip struct {
	// Value is the shared value, as shown to people.
	Value string `json:"value"`
	// Kind is what links the value to its holders: a relation label, or the
	// stored property or attribute a search matched.
	Kind string `json:"kind"`
	// Holders is how many assets hold the value; with More set, at least
	// this many.
	Holders int  `json:"holders"`
	More    bool `json:"more,omitempty"`
	// Limit is the most holders the rule allows, and Derived says whether
	// the database derived it (internal/hubs) or the fixed limit applied.
	Limit   int  `json:"limit"`
	Derived bool `json:"derived"`
}

// String describes the skip in a sentence.
func (h HubSkip) String() string {
	holders := fmt.Sprint(h.Holders)
	if h.More {
		// a search cut short at the limit and one more: more than the limit
		holders = fmt.Sprintf("more than %d", h.Limit)
	}
	source := "fixed"
	if h.Derived {
		source = "from the database"
	}
	return fmt.Sprintf("%s is shared by %s assets (hub limit %d for %s, %s)", h.Value, holders, h.Limit, h.Kind,
		source)
}

// hubSkips collects a run's skips, once per value and kind.
type hubSkips struct {
	seen map[string]bool
	list []HubSkip
}

// add records h unless the same value and kind was recorded.
func (s *hubSkips) add(h HubSkip) {
	key := h.Kind + "\x00" + h.Value
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	if s.seen[key] {
		return
	}
	s.seen[key] = true
	s.list = append(s.list, h)
}

// sorted returns the skips, the most widely shared first.
func (s *hubSkips) sorted() []HubSkip {
	out := append([]HubSkip(nil), s.list...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Holders != out[j].Holders {
			return out[i].Holders > out[j].Holders
		}
		return out[i].Kind+out[i].Value < out[j].Kind+out[j].Value
	})
	return out
}

// hubCheck is the hub rule for one kind of shared value, recording in skips
// the values it stops.
type hubCheck struct {
	rule  graph.HubRule
	kind  string
	skips *hubSkips
}

// signalHub is a signal's hub check (its catalog SignalHub) for the values
// of src, named kind in the report: when the signal lets the limit be
// derived, the database's for those values when it can say, and otherwise
// the signal's limit.
func signalHub(ctx context.Context, g graph.Graph, h SignalHub, src graph.HubSource, kind string,
	skips *hubSkips) hubCheck {
	if !h.Derived {
		return hubCheck{rule: graph.HubRule{Limit: h.Limit}, kind: kind, skips: skips}
	}
	return hubCheck{rule: graph.SourceHubRule(ctx, g, src, h.Limit), kind: kind, skips: skips}
}

// edgeSource is the hub source for the values linked by label in direction.
func edgeSource(label, direction string) graph.HubSource {
	return graph.HubSource{Label: label, Direction: direction}
}

// fingerprintSource is the hub source for the fingerprint Identifiers of one
// id_type: a page title and a favicon spread very differently, so each type
// has its own limit.
func fingerprintSource(idType string) graph.HubSource {
	return graph.HubSource{Label: "fingerprint", Direction: "in", AssetType: "Identifier", Property: "id_type",
		Value: idType}
}

// exceeded reports whether holders exceed the limit (more: a search found
// more than holders).
func (c hubCheck) exceeded(holders int, more bool) bool {
	return more || holders > c.rule.Limit
}

// record records value as stopped by the rule.
func (c hubCheck) record(value string, holders int, more bool) {
	if c.skips != nil {
		c.skips.add(HubSkip{Value: value, Kind: c.kind, Holders: holders, More: more, Limit: c.rule.Limit,
			Derived: c.rule.Derived})
	}
}

// over reports whether value's holders exceed the limit, recording the
// value when they do.
func (c hubCheck) over(value string, holders int, more bool) bool {
	if !c.exceeded(holders, more) {
		return false
	}
	c.record(value, holders, more)
	return true
}

// assetName is the asset id as shown to people, or its ID when it cannot
// be read: for a skip whose value is known only by ID until it is reported.
func assetName(ctx context.Context, g graph.Graph, id string) string {
	if a, err := g.GetAsset(ctx, id); err == nil {
		return graph.AssetLabel(a)
	}
	return id
}

// hubSkipText lists skips for a text answer, at most lensMaxExamples of
// them, or "" for none.
func hubSkipText(skips []HubSkip) string {
	if len(skips) == 0 {
		return ""
	}
	var parts []string
	for i, h := range skips {
		if i == lensMaxExamples {
			parts = append(parts, fmt.Sprintf("and %d more", len(skips)-i))
			break
		}
		parts = append(parts, h.String())
	}
	return fmt.Sprintf(" %d shared value(s) did not count: %s.", len(skips), strings.Join(parts, "; "))
}
