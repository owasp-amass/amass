// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/asset-db/repository"
)

// GraphChanges implements graph.ChangeReader with asset-db's GraphChanges.
// A repository without it answers graph.ErrUnsupported.
func (a Adapter) GraphChanges(ctx context.Context, since time.Time) (graph.GraphChanges, error) {
	reader, ok := a.Repo.(repository.ChangeReader)
	if !ok {
		return graph.GraphChanges{}, graph.ErrUnsupported
	}

	defer a.Stats.record("GraphChanges", time.Now())
	ch, err := reader.GraphChanges(ctx, since)
	if err != nil {
		return graph.GraphChanges{}, err
	}

	return graph.GraphChanges{Now: ch.Now, Deletions: ch.Deletions, IDs: ch.EntityIDs}, nil
}
