// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// RelationProposal proposes a reviewed, reversible relationship
// From --Label--> To between two existing assets, computed by a Goal-2
// correlator from evidence in the Asset Database. It generalizes the account,
// organization-merge and person-merge proposals: every correlator that
// concludes "these two assets stand in this OAM relation" (an organizational
// unit, a related domain's owning organization, a vendor, ...) emits one, so a
// new correlation is a detector plus signal data, not new review plumbing
// (ai-design-principles.md, principles 9 & 10). The proposal is applied only
// when a reviewer accepts it, and every apply records enough to be undone.
type RelationProposal struct {
	ID     string `json:"id"`   // "<kind>-<hash>"
	Kind   string `json:"kind"` // correlator kind, e.g. "org_unit"
	FromID string `json:"from_id"`
	From   string `json:"from"`
	Label  string `json:"label"` // OAM relation label to create
	ToID   string `json:"to_id"`
	To     string `json:"to"`
	// Confidence (0-100) is written on the created edge's SourceProperty.
	Confidence  int      `json:"confidence"`
	Signals     []string `json:"signals,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	// Witness holds the evidence as the stored relationships the conclusion
	// rests on, so a re-check can re-test the proposal when the story changes
	// (see RecheckRelations) and never has to backfill the basis later.
	Witness []graph.WitnessEdge `json:"witness,omitempty"`
	// NewTo, when set, is the destination ApplyRelation creates (ToID is
	// empty): a unit a document names that no source has stored.
	NewTo     *lens.NewAsset `json:"new_to,omitempty"`
	Status    string         `json:"status"`
	CreatedAt time.Time      `json:"created_at"`
}

// RelationOutcome records a reviewer's decision on a relation proposal, and the
// edge it created when applied, so the apply can be undone.
type RelationOutcome struct {
	ProposalID string `json:"proposal_id"`
	Status     string `json:"status"`
	Reviewer   string `json:"reviewer"`
	EdgeID     string `json:"edge_id,omitempty"`
	// CreatedID is the asset the apply created (NewTo), removed on undo.
	CreatedID string    `json:"created_id,omitempty"`
	At        time.Time `json:"at"`
}

// RelationProposalID is a stable identifier for a proposed relationship, built
// from the correlator kind and the directed endpoints and label, so the same
// relationship is proposed once and a rejected or undone one is recognized and
// not proposed again. It is directional: From --Label--> To differs from its
// reverse.
func RelationProposalID(kind, fromID, label, toID string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + fromID + "\x00" + label + "\x00" + toID))
	return kind + "-" + hex.EncodeToString(sum[:8])
}

// IsRelationProposal reports whether an ID names a relation proposal of the
// given correlator kind, so an apply can dispatch on the proposal alone.
func IsRelationProposal(id, kind string) bool {
	return strings.HasPrefix(id, kind+"-")
}

// RelationProposals turns a correlator's relation report into review-gated
// proposals.
func RelationProposals(r lens.RelationReport) []RelationProposal {
	var out []RelationProposal
	now := time.Now().UTC()
	for _, c := range r.Candidates {
		to := c.ToID
		if to == "" && c.NewTo != nil && c.NewTo.Key != "" {
			to = "new:" + c.NewTo.Type + ":" + c.NewTo.Key
		}
		if c.FromID == "" || to == "" || c.Label == "" {
			continue
		}
		out = append(out, RelationProposal{
			ID:          RelationProposalID(r.Kind, c.FromID, c.Label, to),
			Kind:        r.Kind,
			FromID:      c.FromID,
			From:        c.From,
			Label:       c.Label,
			ToID:        c.ToID,
			To:          c.To,
			Confidence:  c.Confidence,
			Signals:     c.Signals,
			EvidenceIDs: c.EvidenceIDs,
			Witness:     c.Witness,
			NewTo:       c.NewTo,
			Status:      ProposalPending,
			CreatedAt:   now,
		})
	}

	return out
}

// relationProposalIDs returns the IDs of the relation proposals already in the
// journal, so SubmitRelations does not record a duplicate.
func (j *Journal) relationProposalIDs() (map[string]bool, error) {
	ids := map[string]bool{}
	hist, err := j.History()
	if errors.Is(err, os.ErrNotExist) {
		return ids, nil
	}
	if err != nil {
		return nil, err
	}

	for _, raw := range hist {
		var rec struct {
			Kind string `json:"kind"`
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if json.Unmarshal(raw, &rec) == nil && rec.Kind == "relation_proposal" && rec.Data.ID != "" {
			ids[rec.Data.ID] = true
		}
	}

	return ids, nil
}

// SubmitRelations records the relation proposals not already in the journal and
// returns the ones it added.
func (j *Journal) SubmitRelations(proposals []RelationProposal) ([]RelationProposal, error) {
	seen, err := j.relationProposalIDs()
	if err != nil {
		return nil, err
	}

	var added []RelationProposal
	for _, p := range proposals {
		if p.ID == "" || p.Kind == "" || p.FromID == "" || (p.ToID == "" && p.NewTo == nil) || p.Label == "" {
			return added, errors.New("relation proposal needs an ID, kind, endpoints and label")
		}
		if seen[p.ID] {
			continue
		}
		if err := j.append("relation_proposal", p); err != nil {
			return added, err
		}
		seen[p.ID] = true
		added = append(added, p)
	}

	return added, nil
}

// RecordRelation records a reviewer's decision on a relation proposal, and the
// edge it created when applied.
func (j *Journal) RecordRelation(o RelationOutcome) error {
	if o.ProposalID == "" || o.Reviewer == "" {
		return errors.New("proposal ID and reviewer required")
	}
	if o.Status != ProposalApplied && o.Status != ProposalRejected && o.Status != ProposalRetracted {
		return fmt.Errorf("invalid relation outcome status %q", o.Status)
	}
	if o.At.IsZero() {
		o.At = time.Now().UTC()
	}

	return j.append("relation_outcome", o)
}

// relationRecords returns the relation proposals in the journal and the latest
// status of each. When kind is non-empty, only that correlator's proposals are
// returned.
func (j *Journal) relationRecords(kind string) (map[string]RelationProposal, map[string]string, error) {
	proposals := map[string]RelationProposal{}
	status := map[string]string{}
	hist, err := j.History()
	if errors.Is(err, os.ErrNotExist) {
		return proposals, status, nil
	}
	if err != nil {
		return nil, nil, err
	}

	for _, raw := range hist {
		var head struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &head) != nil {
			continue
		}
		switch head.Kind {
		case "relation_proposal":
			var p RelationProposal
			if json.Unmarshal(head.Data, &p) == nil && p.ID != "" {
				if kind != "" && p.Kind != kind {
					continue
				}
				proposals[p.ID] = p
				status[p.ID] = ProposalPending
			}
		case "relation_outcome":
			var o RelationOutcome
			if json.Unmarshal(head.Data, &o) == nil && o.ProposalID != "" {
				if _, ok := proposals[o.ProposalID]; ok || kind == "" {
					status[o.ProposalID] = o.Status
				}
			}
		}
	}

	// pending proposals reach the entities merges moved their ends to
	r := readRedirects(hist)
	var items []pendingItem
	for id, p := range proposals {
		if status[id] != ProposalPending {
			continue
		}
		moved := r.redirected(&p.FromID, &p.ToID)
		proposals[id] = p
		to := p.ToID
		if to == "" {
			to = "new:" + p.To
		}
		items = append(items, pendingItem{id: id, key: p.Kind + "|" + p.FromID + "|" + p.Label + "|" + to,
			collapsed: p.FromID == p.ToID, created: p.CreatedAt, moved: moved})
	}
	markSuperseded(items, func(id, _ string, _ time.Time) { status[id] = ProposalSuperseded })

	return proposals, status, nil
}

// RelationState returns the relation proposals of a correlator kind (or all
// kinds when kind is empty) and the latest status of each, for listing pending
// proposals in the CLI and over MCP.
func (j *Journal) RelationState(kind string) (map[string]RelationProposal, map[string]string, error) {
	return j.relationRecords(kind)
}

// PendingRelation returns a relation proposal that is recorded and still
// awaiting a decision.
func (j *Journal) PendingRelation(id string) (RelationProposal, error) {
	proposals, status, err := j.relationRecords("")
	if err != nil {
		return RelationProposal{}, err
	}
	p, ok := proposals[id]
	if !ok {
		return RelationProposal{}, fmt.Errorf("no relation proposal %s", id)
	}
	if status[id] != ProposalPending {
		return RelationProposal{}, fmt.Errorf("relation proposal %s is already %s", id, status[id])
	}

	return p, nil
}

// AppliedRelation returns an applied relation proposal and the edge it created.
func (j *Journal) AppliedRelation(id string) (RelationProposal, string, error) {
	proposals, status, err := j.relationRecords("")
	if err != nil {
		return RelationProposal{}, "", err
	}
	p, ok := proposals[id]
	if !ok || status[id] != ProposalApplied {
		return RelationProposal{}, "", fmt.Errorf("relation proposal %s is not applied", id)
	}

	return p, j.appliedOutcome(id).EdgeID, nil
}

// appliedOutcome returns the latest apply recorded for a relation proposal.
func (j *Journal) appliedOutcome(id string) RelationOutcome {
	hist, _ := j.History()
	var out RelationOutcome
	for _, raw := range hist {
		var head struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &head) != nil || head.Kind != "relation_outcome" {
			continue
		}
		var o RelationOutcome
		if json.Unmarshal(head.Data, &o) == nil && o.ProposalID == id && o.Status == ProposalApplied {
			out = o
		}
	}
	return out
}

// RelationEntry is a relation proposal paired with its latest status, for
// listing proposals in the CLI and over MCP.
type RelationEntry struct {
	Proposal RelationProposal `json:"proposal"`
	Status   string           `json:"status"`
}

// RelationEntries returns the journal's relation proposals and their latest
// status, pending first and then by descending confidence, so review surfaces
// the strongest undecided proposals first. An empty kind returns every
// correlator's proposals.
func (j *Journal) RelationEntries(kind string) ([]RelationEntry, error) {
	proposals, status, err := j.relationRecords(kind)
	if err != nil {
		return nil, err
	}

	out := make([]RelationEntry, 0, len(proposals))
	for id, p := range proposals {
		out = append(out, RelationEntry{Proposal: p, Status: status[id]})
	}

	sort.Slice(out, func(a, b int) bool {
		pa, pb := out[a].Status == ProposalPending, out[b].Status == ProposalPending
		if pa != pb {
			return pa
		}
		if out[a].Proposal.Confidence != out[b].Proposal.Confidence {
			return out[a].Proposal.Confidence > out[b].Proposal.Confidence
		}

		return out[a].Proposal.ID < out[b].Proposal.ID
	})

	return out, nil
}

// FormatRelationEntries renders relation proposals for review, the same shape
// for every correlator kind.
func FormatRelationEntries(entries []RelationEntry) string {
	if len(entries) == 0 {
		return "No relationship proposals in the journal."
	}

	var b strings.Builder
	for _, e := range entries {
		p := e.Proposal
		fmt.Fprintf(&b, "%s [%s, %s] %s --%s--> %s (confidence %d)\n", p.ID, e.Status, p.Kind, p.From, p.Label,
			p.To, p.Confidence)
		if len(p.Signals) > 0 {
			fmt.Fprintf(&b, "  signals: %s\n", strings.Join(p.Signals, "; "))
		}
		for _, ev := range p.EvidenceIDs {
			fmt.Fprintf(&b, "    %s\n", ev)
		}
	}

	return b.String()
}

// RelationApplier writes the edge an accepted relation proposal creates.
type RelationApplier interface {
	FindEntityById(ctx context.Context, id string) (*dbt.Entity, error)
	CreateEdge(ctx context.Context, e *dbt.Edge) (*dbt.Edge, error)
	CreateEdgeProperty(ctx context.Context, e *dbt.Edge, p oam.Property) (*dbt.EdgeTag, error)
}

// RelationDeleter removes the edge an applied relation proposal created.
type RelationDeleter interface {
	DeleteEdge(ctx context.Context, id string) error
}

// assetCreator creates the asset a proposal with NewTo adds; assetDeleter
// removes it on undo. Repositories implement both.
type assetCreator interface {
	CreateAsset(ctx context.Context, asset oam.Asset) (*dbt.Entity, error)
}

type assetDeleter interface {
	DeleteEntity(ctx context.Context, id string) error
}

// newAsset returns the OAM asset a proposal's NewTo describes.
func newAsset(n *lens.NewAsset) (oam.Asset, error) {
	switch n.Type {
	case string(oam.Organization):
		return &oamorg.Organization{ID: n.Key, Name: n.Name}, nil
	}
	return nil, fmt.Errorf("a relation proposal cannot create a %s", n.Type)
}

// ApplyRelation creates the proposed From --Label--> To edge, tagged amass-ai
// with the proposal's confidence, and records the apply so it can be undone. It
// is only ever called for a proposal a human has approved.
func ApplyRelation(ctx context.Context, w RelationApplier, j *Journal, p RelationProposal,
	reviewer string) (string, error) {
	if p.FromID == "" || (p.ToID == "" && p.NewTo == nil) || p.Label == "" {
		return "", errors.New("relation proposal needs endpoints and a label")
	}

	from, err := w.FindEntityById(ctx, p.FromID)
	if err != nil || from == nil {
		return "", fmt.Errorf("from asset %s not found: %w", p.FromID, err)
	}
	var to *dbt.Entity
	createdID := ""
	if p.ToID == "" {
		creator, ok := w.(assetCreator)
		if !ok {
			return "", errors.New("this store cannot create the proposal's new asset")
		}
		asset, err := newAsset(p.NewTo)
		if err != nil {
			return "", err
		}
		if to, err = creator.CreateAsset(ctx, asset); err != nil || to == nil {
			return "", fmt.Errorf("create %s %s: %w", p.NewTo.Type, p.NewTo.Name, err)
		}
		createdID = to.ID
	} else if to, err = w.FindEntityById(ctx, p.ToID); err != nil || to == nil {
		return "", fmt.Errorf("to asset %s not found: %w", p.ToID, err)
	}

	edge, err := w.CreateEdge(ctx, &dbt.Edge{
		Relation:   &oamgen.SimpleRelation{Name: p.Label},
		FromEntity: from,
		ToEntity:   to,
	})
	if err != nil || edge == nil {
		return "", fmt.Errorf("link %s --%s--> %s: %w", p.From, p.Label, p.To, err)
	}
	_, _ = w.CreateEdgeProperty(ctx, edge, &oamgen.SourceProperty{Source: InferenceSource, Confidence: p.Confidence})

	if err := j.RecordRelation(RelationOutcome{ProposalID: p.ID, Status: ProposalApplied, Reviewer: reviewer,
		EdgeID: edge.ID, CreatedID: createdID}); err != nil {
		return edge.ID, fmt.Errorf("%s --%s--> %s was linked but the journal was not updated: %w", p.From, p.Label,
			p.To, err)
	}

	return edge.ID, nil
}

// RetractRelation undoes an applied relation proposal: the edge it created is
// deleted and the retraction recorded.
func RetractRelation(ctx context.Context, w RelationDeleter, j *Journal, id, reviewer string) error {
	p, edgeID, err := j.AppliedRelation(id)
	if err != nil {
		return err
	}
	if edgeID != "" {
		if err := w.DeleteEdge(ctx, edgeID); err != nil {
			return fmt.Errorf("undo relation %s: %w", id, err)
		}
	}
	// the asset the apply created goes too
	if created := j.appliedOutcome(id).CreatedID; created != "" {
		if d, ok := w.(assetDeleter); ok {
			if err := d.DeleteEntity(ctx, created); err != nil {
				return fmt.Errorf("undo relation %s: remove %s: %w", id, p.To, err)
			}
		}
	}
	if err := j.RecordRelation(RelationOutcome{ProposalID: id, Status: ProposalRetracted, Reviewer: reviewer}); err != nil {
		return fmt.Errorf("%s --%s--> %s was unlinked but the journal was not updated: %w", p.From, p.Label, p.To, err)
	}

	return nil
}
