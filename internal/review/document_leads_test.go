// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// leadStore holds lead entities, their tags and whether each has edges.
type leadStore struct {
	entities map[string]*dbt.Entity
	tags     map[string]oam.Property
	edgeTags map[string]oam.Property
	edges    map[string]bool
	sources  map[string]string
	next     int
}

func newLeadStore(ids ...string) *leadStore {
	s := &leadStore{entities: map[string]*dbt.Entity{}, tags: map[string]oam.Property{},
		edgeTags: map[string]oam.Property{}, edges: map[string]bool{}, sources: map[string]string{}}
	for _, id := range ids {
		s.entities[id] = &dbt.Entity{ID: id, Asset: &oamorg.Organization{ID: id, Name: id}}
	}
	return s
}

func (s *leadStore) FindEntityById(_ context.Context, id string) (*dbt.Entity, error) {
	if e, ok := s.entities[id]; ok {
		return e, nil
	}
	return nil, errors.New("entity not found")
}

func (s *leadStore) CreateEntityProperty(_ context.Context, _ *dbt.Entity, p oam.Property) (*dbt.EntityTag, error) {
	s.next++
	id := fmt.Sprintf("t%d", s.next)
	s.tags[id] = p
	return &dbt.EntityTag{ID: id, Property: p}, nil
}

func (s *leadStore) DeleteEntityTag(_ context.Context, id string) error {
	if _, ok := s.tags[id]; !ok {
		return errors.New("tag not found")
	}
	delete(s.tags, id)
	return nil
}

func (s *leadStore) edgeList(e *dbt.Entity) ([]*dbt.Edge, error) {
	if s.edges[e.ID] {
		return []*dbt.Edge{{ID: "e1"}}, nil
	}
	return nil, fmt.Errorf("zero edges found for entity %s", e.ID)
}

func (s *leadStore) IncomingEdges(_ context.Context, e *dbt.Entity, _ time.Time, _ ...string) ([]*dbt.Edge, error) {
	return s.edgeList(e)
}

func (s *leadStore) OutgoingEdges(_ context.Context, e *dbt.Entity, _ time.Time, _ ...string) ([]*dbt.Edge, error) {
	return nil, fmt.Errorf("zero edges found for entity %s", e.ID)
}

func (s *leadStore) DeleteEntity(_ context.Context, id string) error {
	delete(s.entities, id)
	return nil
}

func (s *leadStore) FindEntityTags(_ context.Context, e *dbt.Entity, _ time.Time, _ ...string) ([]*dbt.EntityTag, error) {
	var out []*dbt.EntityTag
	for id, p := range s.tags {
		out = append(out, &dbt.EntityTag{ID: id, Property: p})
	}
	if src, ok := s.sources[e.ID]; ok {
		out = append(out, &dbt.EntityTag{ID: "src-" + e.ID, Property: &oamgen.SourceProperty{Source: src}})
	}
	if len(out) == 0 {
		return nil, errors.New("no tags found for entity")
	}
	return out, nil
}

func (s *leadStore) CreateEdgeProperty(_ context.Context, e *dbt.Edge, p oam.Property) (*dbt.EdgeTag, error) {
	s.next++
	id := fmt.Sprintf("et%d", s.next)
	s.edgeTags[id] = p
	return &dbt.EdgeTag{ID: id, Property: p}, nil
}

func (s *leadStore) DeleteEdgeTag(_ context.Context, id string) error {
	if _, ok := s.edgeTags[id]; !ok {
		return errors.New("edge tag not found")
	}
	delete(s.edgeTags, id)
	return nil
}

// A lead is tagged amass-ai and journaled as applied by the document model;
// retracting it removes the tags, and the Organization too when the engine
// connected nothing to it.
func TestDocumentLeadsRecordAndRetract(t *testing.T) {
	ctx := context.Background()
	s := newLeadStore("Acme Dining Inc.", "SUNY System Administration")
	s.edges["SUNY System Administration"] = true
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}

	var ids []string
	for _, name := range []string{"Acme Dining Inc.", "SUNY System Administration"} {
		l, err := RecordDocumentLead(ctx, s, j, DocumentLead{RunID: "run1", EntityID: name, Name: name, FileID: "f1",
			URL: "https://www.sunyit.edu/a.pdf", Predicate: "supplied_by", Model: "ollama/qwen3:8b"})
		if err != nil {
			t.Fatal(err)
		}
		if !IsDocumentLead(l.ID) || len(l.TagIDs) != 2 || l.Reviewer != DocumentLeadReviewer {
			t.Fatalf("lead %+v", l)
		}
		ids = append(ids, l.ID)
	}
	var sources int
	for _, p := range s.tags {
		if sp, ok := p.(*oamgen.SourceProperty); ok && sp.Source == InferenceSource {
			sources++
		}
	}
	if sources != 2 {
		t.Fatalf("amass-ai sources %d, want 2", sources)
	}

	removed, err := RetractDocumentLead(ctx, s, j, ids[0], "jeff")
	if err != nil || !removed || s.entities["Acme Dining Inc."] != nil {
		t.Fatalf("retract unconnected lead: removed %v, %v", removed, err)
	}
	removed, err = RetractDocumentLead(ctx, s, j, ids[1], "jeff")
	if err != nil || removed || s.entities["SUNY System Administration"] == nil {
		t.Fatalf("retract connected lead: removed %v, %v", removed, err)
	}
	if len(s.tags) != 0 {
		t.Fatalf("retraction left %d tags", len(s.tags))
	}
	if _, err := RetractDocumentLead(ctx, s, j, ids[1], "jeff"); err == nil {
		t.Fatal("a lead was retracted twice")
	}

	leads, _ := j.DocumentLeads()
	if len(leads) != 2 || leads[0].Status != ProposalRetracted || leads[1].Reviewer != "jeff" {
		t.Fatalf("leads %+v", leads)
	}
}

// When a run ends without known targets, a lead the engine linked to other
// assets, or another source reported, is kept and its relations cite the
// document; any other expires.
func TestSettleDocumentLeads(t *testing.T) {
	ctx := context.Background()
	s := newLeadStore("vpn.example.edu", "Acme Dining Inc.", "SUNY System Administration")
	s.edges["vpn.example.edu"] = true
	s.sources["SUNY System Administration"] = "GLEIF"
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	for _, name := range []string{"vpn.example.edu", "Acme Dining Inc.", "SUNY System Administration"} {
		if _, err := RecordDocumentLead(ctx, s, j, DocumentLead{RunID: "run1", EntityID: name, Name: name,
			URL: "https://www.example.edu/a.pdf", Predicate: "named", Model: "m"}); err != nil {
			t.Fatal(err)
		}
	}
	// another run's lead is left alone
	if _, err := RecordDocumentLead(ctx, s, j, DocumentLead{RunID: "run2", EntityID: "Acme Dining Inc.",
		Name: "Acme Dining Inc.", Model: "m"}); err != nil {
		t.Fatal(err)
	}

	confirmed, expired, err := SettleDocumentLeads(ctx, s, j, "run1", LeadTargets{})
	if err != nil || confirmed != 2 || expired != 1 {
		t.Fatalf("confirmed %d, expired %d, %v", confirmed, expired, err)
	}
	if s.entities["Acme Dining Inc."] != nil {
		t.Error("the unconfirmed lead's asset was kept")
	}
	if len(s.edgeTags) != 1 {
		t.Errorf("relation tags %d, want the vpn host's one edge", len(s.edgeTags))
	}

	leads, _ := j.DocumentLeads()
	byID := map[string]DocumentLead{}
	for _, l := range leads {
		byID[l.ID] = l
	}
	if l := byID["doclead:run1:vpn.example.edu"]; !l.Confirmed || len(l.EdgeTagIDs) != 1 || l.Status != ProposalApplied ||
		l.Footprint == nil || l.Footprint.Relations != 1 || l.SubmittedAt.IsZero() {
		t.Errorf("confirmed lead %+v", l)
	}
	if l := byID["doclead:run1:Acme Dining Inc."]; l.Status != ProposalRetracted || l.Reviewer != DocumentLeadExpiredReviewer {
		t.Errorf("expired lead %+v", l)
	}
	if l := byID["doclead:run2:Acme Dining Inc."]; l.Status != ProposalApplied || l.Confirmed {
		t.Errorf("another run's lead was settled: %+v", l)
	}

	// retracting a confirmed lead removes its relation tags too
	if _, err := RetractDocumentLead(ctx, s, j, "doclead:run1:vpn.example.edu", "jeff"); err != nil {
		t.Fatal(err)
	}
	if len(s.edgeTags) != 0 {
		t.Errorf("retraction left %d relation tags", len(s.edgeTags))
	}
}
