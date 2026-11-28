// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// sweepPruneQuiet is how long nothing may have been recorded on a dead
// address before it is removed while the session runs.
const sweepPruneQuiet = 5 * time.Minute

// pruneDead removes a dead swept address, and its reverse DNS alias, when
// the session that started at since stored them and nothing else was
// recorded about them: the only relation to the address is its netblock's
// contains, the only ones from it are the ptr_record to an alias no answer
// was stored for and a geolocation, and no property was added to it since
// quietSince. Every asset is stored before it is investigated; this
// takes back the ones the sweep stored that turned out to be nothing. It
// reports whether the address was removed.
func pruneDead(ctx context.Context, db SweepDB, addr string, since, quietSince time.Time) bool {
	ents, err := db.FindEntitiesByContent(ctx, oam.IPAddress, time.Time{}, 1, dbt.ContentFilters{"address": addr})
	if err != nil || len(ents) == 0 {
		return false
	}
	ip := ents[0]
	if ip.CreatedAt.Before(since) {
		return false
	}

	in, _ := db.IncomingEdges(ctx, ip, time.Time{})
	for _, e := range in {
		if e.Relation == nil || e.Relation.Label() != "contains" {
			return false
		}
	}

	var aliases []string
	out, _ := db.OutgoingEdges(ctx, ip, time.Time{})
	for _, e := range out {
		// where a geolocation source places any address says nothing of it
		if e.Relation != nil && e.Relation.Label() == "geolocation" {
			continue
		}
		if e.Relation == nil || e.Relation.Label() != "ptr_record" || e.ToEntity == nil {
			return false
		}
		if !unansweredAlias(ctx, db, e.ToEntity.ID, since) {
			return false
		}
		aliases = append(aliases, e.ToEntity.ID)
	}

	if tags, _ := db.FindEntityTags(ctx, ip, quietSince); len(tags) > 0 {
		return false
	}

	for _, id := range aliases {
		if db.DeleteEntity(ctx, id) != nil {
			return false
		}
	}
	return db.DeleteEntity(ctx, ip.ID) == nil
}

// unansweredAlias reports whether a reverse DNS alias was stored by the
// session that started at since and leads nowhere: no PTR answer was stored
// for it, and only its address relates to it.
func unansweredAlias(ctx context.Context, db SweepDB, id string, since time.Time) bool {
	alias, err := db.FindEntityById(ctx, id)
	if err != nil || alias == nil || alias.CreatedAt.Before(since) {
		return false
	}
	if out, _ := db.OutgoingEdges(ctx, alias, time.Time{}); len(out) > 0 {
		return false
	}
	in, _ := db.IncomingEdges(ctx, alias, time.Time{})
	return len(in) == 1
}
