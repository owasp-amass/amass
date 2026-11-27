// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// contributionJudge tells the strong signals that rest on what assistants
// contributed (sources amass-ai:<client>). Unless the graph lets
// contributions be strong evidence (options.ai.contributions.strong_evidence),
// such a signal counts as supporting: it adds its weight and corroborates,
// but cannot be the strong signal. It reads a record's sources once per
// search, and only for the evidence of strong signals.
//
// A signal's evidence holds one or more ways (each occurrence of the
// signal), and a way needs each of its links (a witness chain needs every
// edge). A link that only contributions recorded makes its way rest on
// contributions; the signal does when every way does.
type contributionJudge struct {
	ctx context.Context
	// g is nil when contributions may be strong: then no signal is judged
	// contributed.
	g     graph.Graph
	edges graph.EdgeEvidenceReader
	only  map[string]bool
}

var errNoEdgeSources = errors.New("the graph cannot read edge sources")

// evidenceLink is one necessary part of a signal's evidence: the stored
// edges, or the entities, any one of which records it.
type evidenceLink struct {
	edges, entities []string
}

// signalSupport is the ways a signal's evidence holds, each a list of the
// links it needs.
type signalSupport [][]evidenceLink

func newContributionJudge(ctx context.Context, g graph.Graph) *contributionJudge {
	j := &contributionJudge{ctx: ctx, only: map[string]bool{}}
	if !graph.ContributionsStrong(g) {
		j.g = g
		j.edges, _ = g.(graph.EdgeEvidenceReader)
	}
	return j
}

// witnessSupport is the one way a witness chain holds: each edge a link. A
// witness with no stored ID is no link, so it never rests on contributions.
func witnessSupport(witness []graph.WitnessEdge) []evidenceLink {
	way := make([]evidenceLink, 0, len(witness))
	for _, w := range witness {
		if w.EdgeID != "" {
			way = append(way, evidenceLink{edges: []string{w.EdgeID}})
		}
	}
	return way
}

// contributed reports whether every way of the support rests on
// contributions.
func (j *contributionJudge) contributed(s signalSupport) bool {
	if j == nil || j.g == nil || len(s) == 0 {
		return false
	}
	for _, way := range s {
		if !j.wayContributed(way) {
			return false
		}
	}
	return true
}

func (j *contributionJudge) wayContributed(way []evidenceLink) bool {
	for _, l := range way {
		if j.linkContributed(l) {
			return true
		}
	}
	return false
}

// linkContributed reports whether every record of the link only
// contributions recorded.
func (j *contributionJudge) linkContributed(l evidenceLink) bool {
	if len(l.edges)+len(l.entities) == 0 {
		return false
	}
	for _, id := range l.edges {
		if !j.contributedOnly("edge\x00"+id, func() ([]graph.Evidence, error) {
			if j.edges == nil {
				return nil, errNoEdgeSources
			}
			return j.edges.EdgeEvidence(j.ctx, id, graph.MaxEdgeRead)
		}) {
			return false
		}
	}
	for _, id := range l.entities {
		if !j.contributedOnly("entity\x00"+id, func() ([]graph.Evidence, error) {
			return j.g.Evidence(j.ctx, id, graph.MaxEdgeRead)
		}) {
			return false
		}
	}
	return true
}

// contributedOnly reports whether a record's sources are all contributions;
// a record with no source, or whose sources cannot be read, is not.
func (j *contributionJudge) contributedOnly(key string, read func() ([]graph.Evidence, error)) bool {
	if only, ok := j.only[key]; ok {
		return only
	}

	only := false
	if ev, err := read(); err == nil {
		for _, e := range ev {
			if e.SourceID == "" {
				continue
			}
			if !graph.IsContributionSource(e.SourceID) {
				only = false
				break
			}
			only = true
		}
	}
	j.only[key] = only
	return only
}

// mark sets Contributed on each strong signal that rests on contributions:
// by its support when it has one, else by its witness chain.
func (j *contributionJudge) mark(signals []GapSignal, lookup func(string) (OwnershipSignal, bool)) {
	for i, s := range signals {
		def, ok := lookup(s.Signal)
		if !ok || def.Strength != StrengthStrong {
			continue
		}
		support := s.support
		if len(support) == 0 {
			support = signalSupport{witnessSupport(s.Witness)}
		}
		signals[i].Contributed = j.contributed(support)
	}
}

// signalWitnesses gathers each candidate's witness chains by signal, for
// the scorers that keep one list of signal IDs per candidate.
type signalWitnesses map[string]signalSupport

func (s signalWitnesses) add(candidate, signalID string, witness []graph.WitnessEdge) {
	key := candidate + "\x00" + signalID
	s[key] = append(s[key], witnessSupport(witness))
}

// contributed returns the candidate's strong signals among ids that rest on
// contributions.
func (s signalWitnesses) contributed(j *contributionJudge, candidate string, ids []string,
	lookup func(string) (OwnershipSignal, bool)) []string {
	var out []string
	for _, id := range ids {
		if def, ok := lookup(id); ok && def.Strength == StrengthStrong && j.contributed(s[candidate+"\x00"+id]) {
			out = append(out, id)
		}
	}
	return out
}
