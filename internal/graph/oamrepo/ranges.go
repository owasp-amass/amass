// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"net/netip"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/asset-db/repository"
)

var (
	_ graph.RangeReader = Adapter{}
	_ graph.RunReader   = Adapter{}
)

// AddressesInRange implements graph.RangeReader with asset-db's
// IPRangeReader.
func (a Adapter) AddressesInRange(ctx context.Context, prefix netip.Prefix, limit int) ([]graph.Asset, bool, error) {
	r, ok := a.Repo.(repository.IPRangeReader)
	if !ok {
		return nil, false, graph.ErrUnsupported
	}

	defer a.Stats.record("AddressesInRange", time.Now())

	ents, more, err := r.FindAddressesInRange(ctx, prefix, limit)
	if err != nil {
		return nil, false, err
	}

	return convertAll(ents, more)
}

// NetblocksContaining implements graph.RangeReader.
func (a Adapter) NetblocksContaining(ctx context.Context, addr netip.Addr, limit int) ([]graph.Asset, error) {
	r, ok := a.Repo.(repository.IPRangeReader)
	if !ok {
		return nil, graph.ErrUnsupported
	}

	defer a.Stats.record("NetblocksContaining", time.Now())

	ents, err := r.FindNetblocksContaining(ctx, addr, limit)
	if err != nil {
		return nil, err
	}

	out, _, err := convertAll(ents, false)
	return out, err
}

// CollectionRuns implements graph.RunReader with asset-db's RunRecorder.
func (a Adapter) CollectionRuns(ctx context.Context, since time.Time, limit int) ([]graph.CollectionRun, error) {
	r, ok := a.Repo.(repository.RunRecorder)
	if !ok {
		return nil, graph.ErrUnsupported
	}

	defer a.Stats.record("CollectionRuns", time.Now())

	runs, err := r.FindRuns(ctx, since, limit)
	if err != nil {
		return nil, err
	}

	out := make([]graph.CollectionRun, 0, len(runs))
	for _, run := range runs {
		c := graph.CollectionRun{ID: run.ID, Tool: run.Tool, ToolVersion: run.ToolVersion, ExternalID: run.ExternalID,
			Status: run.Status, StartedAt: run.StartedAt, FinishedAt: run.FinishedAt}
		for _, t := range run.Scope {
			c.Scope = append(c.Scope, graph.RunTarget{Type: string(t.Type), Key: t.Key})
		}

		out = append(out, c)
	}

	return out, nil
}
