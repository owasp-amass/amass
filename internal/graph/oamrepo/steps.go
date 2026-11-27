// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	dbt "github.com/owasp-amass/asset-db/types"
)

// StepsFrom implements graph.StepReader with asset-db's ReadSteps, in one
// query per batch of IDs (and of steps, past types.MaxSteps). A repository without it answers
// graph.ErrStepsUnsupported.
func (a Adapter) StepsFrom(ctx context.Context, ids []string, steps []graph.Step) ([]graph.Relation, error) {
	reader, ok := a.Repo.(interface {
		ReadSteps(context.Context, []string, []dbt.Step, time.Time) ([]*dbt.Edge, error)
	})
	if !ok {
		return nil, graph.ErrStepsUnsupported
	}

	defer a.Stats.record("StepsFrom", time.Now())
	ds := make([]dbt.Step, 0, len(steps))
	for _, s := range steps {
		ds = append(ds, dbt.Step{FromType: s.FromType, Label: s.Label, RelationType: s.RelationType,
			ToType: s.ToType, Forward: s.Forward})
	}

	var out []graph.Relation
	seen := map[string]bool{}
	for chunk := range slices.Chunk(ids, maxBatchIDs) {
		for some := range slices.Chunk(ds, dbt.MaxSteps) {
			edges, err := reader.ReadSteps(ctx, chunk, some, time.Time{})
			if err != nil {
				return nil, err
			}
			for _, e := range edges {
				if e == nil || e.Relation == nil || e.FromEntity == nil || e.ToEntity == nil {
					return nil, errors.New("malformed step edge")
				}
				if seen[e.ID] {
					continue
				}
				seen[e.ID] = true
				out = append(out, relationOf(e, ""))
			}
		}
	}
	return out, nil
}
