// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"slices"
	"time"
)

// RelationSupport is another correlator's conclusion about a relationship
// already proposed: its signals and evidence are added to that proposal, so
// one relationship is one proposal however many correlators reach it.
type RelationSupport struct {
	ProposalID  string    `json:"proposal_id"`
	Kind        string    `json:"kind"`
	Confidence  int       `json:"confidence"`
	Signals     []string  `json:"signals,omitempty"`
	EvidenceIDs []string  `json:"evidence_ids,omitempty"`
	At          time.Time `json:"at"`
}

// fold adds the support to the proposal: its signals, the evidence it does
// not already cite, and its confidence when higher. The proposal's witness
// is its own, so a re-check tests what it was first proposed on.
func (s RelationSupport) fold(p RelationProposal) RelationProposal {
	if slices.Contains(p.AlsoBy, s.Kind) {
		return p
	}

	p.AlsoBy = append(slices.Clone(p.AlsoBy), s.Kind)
	p.Signals = append(slices.Clone(p.Signals), s.Signals...)
	for _, id := range s.EvidenceIDs {
		if !slices.Contains(p.EvidenceIDs, id) {
			p.EvidenceIDs = append(p.EvidenceIDs, id)
		}
	}
	p.Confidence = max(p.Confidence, s.Confidence)
	return p
}

// relationEdgeKey names the relationship a proposal concludes: its ends and
// label, whatever correlator concluded it. A unit to create is named by its
// type and key.
func relationEdgeKey(p RelationProposal) string {
	to := p.ToID
	if to == "" && p.NewTo != nil {
		to = "new:" + p.NewTo.Type + ":" + p.NewTo.Key
	}
	return p.FromID + "\x00" + p.Label + "\x00" + to
}

// relationEdge is the proposal recorded first for a relationship.
type relationEdge struct {
	proposal RelationProposal
	status   string
}

// relationEdgeIndex holds, by relationship, the proposal recorded first.
type relationEdgeIndex map[string]relationEdge

// relationEdges indexes the journal's relation proposals by relationship,
// with their ends where merges moved them.
func (j *Journal) relationEdges() (relationEdgeIndex, error) {
	proposals, status, err := j.relationRecords("")
	if err != nil {
		return nil, err
	}

	idx := relationEdgeIndex{}
	for id, p := range proposals {
		k := relationEdgeKey(p)
		if cur, ok := idx[k]; !ok || p.CreatedAt.Before(cur.proposal.CreatedAt) {
			idx[k] = relationEdge{proposal: p, status: status[id]}
		}
	}
	return idx, nil
}

// add records a proposal just submitted.
func (idx relationEdgeIndex) add(p RelationProposal, status string) {
	if _, ok := idx[relationEdgeKey(p)]; !ok {
		idx[relationEdgeKey(p)] = relationEdge{proposal: p, status: status}
	}
}

// support reports whether p's relationship was proposed already by another
// correlator, recording p's evidence on that proposal while it is pending.
func (idx relationEdgeIndex) support(j *Journal, p RelationProposal) (bool, error) {
	k := relationEdgeKey(p)
	e, ok := idx[k]
	if !ok || e.proposal.ID == p.ID {
		return false, nil
	}
	if e.status != ProposalPending || e.proposal.Kind == p.Kind || slices.Contains(e.proposal.AlsoBy, p.Kind) {
		return true, nil
	}

	s := RelationSupport{ProposalID: e.proposal.ID, Kind: p.Kind, Confidence: p.Confidence, Signals: p.Signals,
		EvidenceIDs: p.EvidenceIDs, At: time.Now().UTC()}
	if err := j.append("relation_support", s); err != nil {
		return false, err
	}
	e.proposal = s.fold(e.proposal)
	idx[k] = e
	return true, nil
}
