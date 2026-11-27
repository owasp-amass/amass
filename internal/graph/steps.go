// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Step is one way a walk over the graph by type rules moves along an edge:
// from an asset of FromType along an edge of RelationType labeled Label to
// one of ToType, forward from the edge's source or backward from its
// destination (asset-db's types.Step). Names compare without case.
type Step struct {
	FromType     string
	Label        string
	RelationType string
	ToType       string
	Forward      bool
}

func (s Step) key() Step {
	return Step{FromType: strings.ToLower(s.FromType), Label: strings.ToLower(s.Label),
		RelationType: strings.ToLower(s.RelationType), ToType: strings.ToLower(s.ToType), Forward: s.Forward}
}

// StepReader reads, for many assets at once, every edge one of the steps
// follows from them (forward from an edge's source, backward from its
// destination), each once, with no limit per asset. ErrStepsUnsupported
// means the store behind it cannot.
type StepReader interface {
	StepsFrom(ctx context.Context, ids []string, steps []Step) ([]Relation, error)
}

// ErrStepsUnsupported is a StepReader's answer when its store cannot read
// steps; StepsFrom then reads each asset's edges instead.
var ErrStepsUnsupported = errors.New("the graph cannot read steps")

// StepSet holds steps for matching an edge against them.
type StepSet map[Step]bool

// NewStepSet returns the set of steps.
func NewStepSet(steps []Step) StepSet {
	set := make(StepSet, len(steps))
	for _, s := range steps {
		set[s.key()] = true
	}
	return set
}

// Follows reports whether a step of the set moves along edge e between
// assets of fromType (its source) and toType (its destination), forward or
// backward.
func (set StepSet) Follows(e Relation, fromType, toType string, forward bool) bool {
	return set[Step{FromType: fromType, Label: e.Label, RelationType: e.Type, ToType: toType,
		Forward: forward}.key()]
}

// StepsFrom returns, each once, the edges a step follows from the assets
// ids: with g's StepReader when it has one, otherwise by reading each
// asset's edges and the assets at their ends, and matching them by type.
func StepsFrom(ctx context.Context, g Graph, ids []string, steps []Step) ([]Relation, error) {
	if r, ok := g.(StepReader); ok {
		edges, err := r.StepsFrom(ctx, ids, steps)
		if !errors.Is(err, ErrStepsUnsupported) {
			return edges, err
		}
	}

	set := NewStepSet(steps)
	types := map[string]string{}
	typeOf := func(id string) (string, error) {
		if t, ok := types[id]; ok {
			return t, nil
		}
		a, err := g.GetAsset(ctx, id)
		if err != nil {
			return "", err
		}
		types[id] = a.Type
		return a.Type, nil
	}

	var out []Relation
	seen := map[string]bool{}
	for _, id := range ids {
		edges, err := g.Edges(ctx, id, "both", "", time.Time{})
		if err != nil {
			return nil, err
		}
		for _, e := range edges {
			key := e.ID + "\x00" + e.FromID + "\x00" + e.ToID + "\x00" + e.Label
			if seen[key] || e.FromID == e.ToID {
				continue
			}
			from, err := typeOf(e.FromID)
			if err != nil {
				return nil, err
			}
			to, err := typeOf(e.ToID)
			if err != nil {
				return nil, err
			}
			if (e.FromID == id && set.Follows(e, from, to, true)) || (e.ToID == id && set.Follows(e, from, to, false)) {
				seen[key] = true
				out = append(out, e)
			}
		}
	}
	return out, nil
}
