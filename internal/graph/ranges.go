// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// ErrUnsupported is returned by an optional read the graph cannot make.
var ErrUnsupported = errors.New("the graph does not support this read")

// RangeReader finds stored addresses and netblocks by range, whatever edges
// connect them.
type RangeReader interface {
	// AddressesInRange returns the IPAddress assets within prefix in address
	// order, at most limit (1..1000); more reports others.
	AddressesInRange(ctx context.Context, prefix netip.Prefix, limit int) ([]Asset, bool, error)
	// NetblocksContaining returns the Netblock assets holding addr, the most
	// specific first, at most limit (1..1000).
	NetblocksContaining(ctx context.Context, addr netip.Addr, limit int) ([]Asset, error)
}

// CollectionRun is one recorded run of a tool that collected into the
// graph: what it was asked to collect, when, and how it ended.
type CollectionRun struct {
	ID          string      `json:"id"`
	Tool        string      `json:"tool"`
	ToolVersion string      `json:"tool_version,omitempty"`
	ExternalID  string      `json:"external_id,omitempty"`
	Status      string      `json:"status"`
	StartedAt   time.Time   `json:"started_at"`
	FinishedAt  time.Time   `json:"finished_at"`
	Scope       []RunTarget `json:"scope,omitempty"`
}

// RunTarget is one asset of a run's scope: an Open Asset Model type and key.
type RunTarget struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}

// RunFinished is the status of a run that did all its work.
const RunFinished = "finished"

// RunReader reads the collection runs recorded in the graph.
type RunReader interface {
	// CollectionRuns returns the runs started at or after since (all when
	// zero), newest first, at most limit.
	CollectionRuns(ctx context.Context, since time.Time, limit int) ([]CollectionRun, error)
}

// AddressesInRange implements RangeReader for a cached graph.
func (c *cachedGraph) AddressesInRange(ctx context.Context, prefix netip.Prefix, limit int) ([]Asset, bool, error) {
	r, ok := c.inner.(RangeReader)
	if !ok {
		return nil, false, ErrUnsupported
	}

	return r.AddressesInRange(ctx, prefix, limit)
}

// NetblocksContaining implements RangeReader for a cached graph.
func (c *cachedGraph) NetblocksContaining(ctx context.Context, addr netip.Addr, limit int) ([]Asset, error) {
	r, ok := c.inner.(RangeReader)
	if !ok {
		return nil, ErrUnsupported
	}

	return r.NetblocksContaining(ctx, addr, limit)
}

// CollectionRuns implements RunReader for a cached graph.
func (c *cachedGraph) CollectionRuns(ctx context.Context, since time.Time, limit int) ([]CollectionRun, error) {
	r, ok := c.inner.(RunReader)
	if !ok {
		return nil, ErrUnsupported
	}

	return r.CollectionRuns(ctx, since, limit)
}
