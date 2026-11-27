// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// DocumentLeadPrefix starts the ID of a lead the document model gave a
// running enumeration.
const DocumentLeadPrefix = "doclead:"

// DocumentReadingPrefix starts the ID of a stored document reading.
const DocumentReadingPrefix = "doc:"

// PropDocLead is the property naming the document statement a lead came from.
const PropDocLead = "doc_lead"

// DocumentLeadReviewer is the reviewer recorded for leads, so they count with
// the other changes the AI made on its own.
const DocumentLeadReviewer = "amass-ai (document model)"

// documentLeadConfidence is the confidence of the amass-ai source on a lead:
// a document named it, which is reason to look, not a conclusion.
const documentLeadConfidence = 50

// IsDocumentLead reports whether id names a document lead.
func IsDocumentLead(id string) bool { return strings.HasPrefix(id, DocumentLeadPrefix) }

// IsDocumentReading reports whether id names a stored document reading.
func IsDocumentReading(id string) bool { return strings.HasPrefix(id, DocumentReadingPrefix) }

// DocumentLead journals an asset a validated document finding named that the
// database did not hold (a domain, an address, a network, an organization, a
// street address, a phone, an email, a URL), submitted to a running
// enumeration so the engine checks it like any other lead. It holds no quote.
type DocumentLead struct {
	ID        string   `json:"id"`
	RunID     string   `json:"run_id"`
	EntityID  string   `json:"entity_id"`
	Name      string   `json:"name"`
	Type      string   `json:"type,omitempty"`
	FileID    string   `json:"file_id"`
	URL       string   `json:"url"`
	Predicate string   `json:"predicate"`
	Model     string   `json:"model"`
	TagIDs    []string `json:"tag_ids,omitempty"`
	// Confirmed is set when the run ended with the engine having tied the
	// lead to the run's targets (LeadConfirmed);
	// EdgeTagIDs are the doc_lead properties then put on those relations.
	Confirmed  bool     `json:"confirmed,omitempty"`
	EdgeTagIDs []string `json:"edge_tag_ids,omitempty"`
	// SubmittedAt is when the lead was given to the run; Footprint is what
	// the engine collected from it, recorded when a confirmed lead settles.
	SubmittedAt time.Time      `json:"submitted_at,omitzero"`
	Footprint   *LeadFootprint `json:"footprint,omitempty"`
	Status      string         `json:"status"`
	Reviewer    string         `json:"reviewer"`
	At          time.Time      `json:"at"`
}

// DocumentLeadStore tags leads, settles them when their run ends and removes
// them again.
type DocumentLeadStore interface {
	DocumentStatementStore
	IncomingEdges(ctx context.Context, entity *dbt.Entity, since time.Time, labels ...string) ([]*dbt.Edge, error)
	OutgoingEdges(ctx context.Context, entity *dbt.Entity, since time.Time, labels ...string) ([]*dbt.Edge, error)
	DeleteEntity(ctx context.Context, id string) error
	FindEntityTags(ctx context.Context, entity *dbt.Entity, since time.Time, names ...string) ([]*dbt.EntityTag, error)
	CreateEdgeProperty(ctx context.Context, edge *dbt.Edge, property oam.Property) (*dbt.EdgeTag, error)
	DeleteEdgeTag(ctx context.Context, id string) error
}

// DocumentLeadExpiredReviewer is recorded for a lead retracted because the
// engine had confirmed nothing about it when its run ended.
const DocumentLeadExpiredReviewer = "amass-ai (unconfirmed when the run ended)"

// documentLeadValue is the value of a doc_lead property.
type documentLeadValue struct {
	URL       string `json:"url"`
	Predicate string `json:"predicate"`
	Model     string `json:"model"`
	Run       string `json:"run"`
}

// RecordDocumentLead tags the submitted lead's entity with an amass-ai source
// and a doc_lead property naming the document, and journals the lead as
// applied by the document model, so it is listed with the AI's other changes
// and can be retracted.
func RecordDocumentLead(ctx context.Context, w DocumentStatementStore, j *Journal, l DocumentLead) (DocumentLead, error) {
	if l.EntityID == "" || l.Name == "" || l.RunID == "" {
		return l, errors.New("a document lead needs its entity, name and run")
	}

	ent, err := w.FindEntityById(ctx, l.EntityID)
	if err != nil || ent == nil {
		return l, fmt.Errorf("lead %s not found: %w", l.EntityID, err)
	}

	value, err := json.Marshal(documentLeadValue{URL: l.URL, Predicate: l.Predicate, Model: l.Model, Run: l.RunID})
	if err != nil {
		return l, err
	}
	for _, p := range []oam.Property{
		&oamgen.SourceProperty{Source: InferenceSource, Confidence: documentLeadConfidence},
		&oamgen.SimpleProperty{PropertyName: PropDocLead, PropertyValue: string(value)},
	} {
		if tag, err := w.CreateEntityProperty(ctx, ent, p); err == nil && tag != nil {
			l.TagIDs = append(l.TagIDs, tag.ID)
		}
	}

	l.At = time.Now().UTC()
	l.SubmittedAt = l.At
	l.ID = DocumentLeadPrefix + l.RunID + ":" + l.EntityID
	l.Status, l.Reviewer = ProposalApplied, DocumentLeadReviewer
	if err := j.append("doc_lead", l); err != nil {
		return l, fmt.Errorf("journal document lead: %w", err)
	}
	return l, nil
}

// DocumentLeads returns the latest record of each document lead, oldest first.
func (j *Journal) DocumentLeads() ([]DocumentLead, error) {
	hist, err := j.History()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	byID := map[string]DocumentLead{}
	var order []string
	for _, raw := range hist {
		var head struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &head) != nil || head.Kind != "doc_lead" {
			continue
		}
		var l DocumentLead
		if json.Unmarshal(head.Data, &l) != nil || l.ID == "" {
			continue
		}
		if _, ok := byID[l.ID]; !ok {
			order = append(order, l.ID)
		}
		byID[l.ID] = l
	}

	out := make([]DocumentLead, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out, nil
}

// RetractDocumentLead removes the amass-ai tags a lead added, and the lead's
// asset itself when nothing links to or from it (the engine found nothing for
// it); an asset the engine connected stays, as one the engine observed. It journals the retraction and reports whether the entity
// was removed.
func RetractDocumentLead(ctx context.Context, w DocumentLeadStore, j *Journal, id, reviewer string) (bool, error) {
	if strings.TrimSpace(reviewer) == "" {
		return false, errors.New("reviewer required")
	}

	leads, err := j.DocumentLeads()
	if err != nil {
		return false, err
	}
	var lead *DocumentLead
	for i := range leads {
		if leads[i].ID == id {
			lead = &leads[i]
		}
	}
	if lead == nil {
		return false, fmt.Errorf("no document lead %s", id)
	}
	if lead.Status != ProposalApplied {
		return false, fmt.Errorf("document lead %s is already %s", id, lead.Status)
	}

	for _, tag := range lead.TagIDs {
		if err := w.DeleteEntityTag(ctx, tag); err != nil && !isNotFound(err) {
			return false, fmt.Errorf("remove lead tag %s: %w", tag, err)
		}
	}
	for _, tag := range lead.EdgeTagIDs {
		if err := w.DeleteEdgeTag(ctx, tag); err != nil && !isNotFound(err) {
			return false, fmt.Errorf("remove lead relation tag %s: %w", tag, err)
		}
	}

	removed := false
	if ent, err := w.FindEntityById(ctx, lead.EntityID); err == nil && ent != nil {
		in, ierr := w.IncomingEdges(ctx, ent, time.Time{})
		out, oerr := w.OutgoingEdges(ctx, ent, time.Time{})
		if noEdges(in, ierr) && noEdges(out, oerr) {
			if err := w.DeleteEntity(ctx, lead.EntityID); err != nil && !isNotFound(err) {
				return false, fmt.Errorf("remove lead %s: %w", lead.Name, err)
			}
			removed = true
		}
	}

	lead.Status, lead.Reviewer, lead.At = ProposalRetracted, reviewer, time.Now().UTC()
	return removed, j.append("doc_lead", *lead)
}

// noEdges reports an edge query that found none; the repositories answer an
// entity without edges with a "zero edges" error. Any other error counts as
// edges present, so a failed query never removes an asset.
func noEdges(edges []*dbt.Edge, err error) bool {
	if err != nil {
		return strings.Contains(strings.ToLower(err.Error()), "zero edges")
	}
	return len(edges) == 0
}

// SettleDocumentLeads decides, when a run ends, each lead the document model
// gave it. A lead is confirmed when the engine tied it to the run's targets
// (see LeadConfirmed): the doc_lead property is then also put on each
// relation that touches it, so what the lead led to cites the document. Any
// other lead is retracted as expired, removing the asset when nothing links
// to it; the finding stays on the File, so a later run can raise it again.
func SettleDocumentLeads(ctx context.Context, w DocumentLeadStore, j *Journal, runID string,
	targets LeadTargets) (confirmed, expired int, err error) {
	leads, err := j.DocumentLeads()
	if err != nil {
		return 0, 0, err
	}

	for _, l := range leads {
		if l.RunID != runID || l.Status != ProposalApplied || l.Confirmed {
			continue
		}
		if ctx.Err() != nil {
			return confirmed, expired, ctx.Err()
		}

		ent, err := w.FindEntityById(ctx, l.EntityID)
		if err != nil || ent == nil {
			// already gone: nothing to keep
			l.Status, l.Reviewer, l.At = ProposalRetracted, DocumentLeadExpiredReviewer, time.Now().UTC()
			if err := j.append("doc_lead", l); err != nil {
				return confirmed, expired, err
			}
			expired++
			continue
		}

		edges := entityEdges(ctx, w, ent)
		if !confirmedEntity(ctx, w, ent, edges, targets) {
			if _, err := RetractDocumentLead(ctx, w, j, l.ID, DocumentLeadExpiredReviewer); err != nil {
				return confirmed, expired, err
			}
			expired++
			continue
		}

		value, err := json.Marshal(documentLeadValue{URL: l.URL, Predicate: l.Predicate, Model: l.Model, Run: l.RunID})
		if err != nil {
			return confirmed, expired, err
		}
		for _, e := range edges {
			if tag, err := w.CreateEdgeProperty(ctx, e, &oamgen.SimpleProperty{PropertyName: PropDocLead,
				PropertyValue: string(value)}); err == nil && tag != nil {
				l.EdgeTagIDs = append(l.EdgeTagIDs, tag.ID)
			}
		}
		since := l.SubmittedAt
		if since.IsZero() {
			since = l.At
		}
		fp := leadFootprint(ctx, w, ent, since)
		l.Footprint = &fp
		l.Confirmed, l.At = true, time.Now().UTC()
		if err := j.append("doc_lead", l); err != nil {
			return confirmed, expired, err
		}
		confirmed++
	}
	return confirmed, expired, nil
}

// knownEdges returns the edges an edge query found; a failed query or "zero
// edges" gives none.
func knownEdges(edges []*dbt.Edge, err error) []*dbt.Edge {
	if err != nil {
		return nil
	}
	return edges
}

// otherSource reports whether a source other than amass-ai reported the
// entity. A lookup that fails counts as another source, so an error never
// removes an asset.
func otherSource(ctx context.Context, w DocumentLeadStore, ent *dbt.Entity) bool {
	tags, err := w.FindEntityTags(ctx, ent, time.Time{})
	if err != nil {
		msg := strings.ToLower(err.Error())
		return !strings.Contains(msg, "no tags") && !strings.Contains(msg, "zero")
	}
	for _, t := range tags {
		if sp, ok := t.Property.(*oamgen.SourceProperty); ok && sp.Source != InferenceSource {
			return true
		}
	}
	return false
}

// LeadConfirmed reports whether the engine has confirmed a lead. With the
// run's targets known, it must have tied the lead to one of them: the lead is
// a target asset the engine linked to others, or stored relations join it to
// a target asset within a few steps. Linking the lead to anything at all is
// not enough, since an organization named in passing collects records of its
// own (its funding, its registrations) that say nothing about the target.
// Without targets, any relation or another source than amass-ai confirms it.
// A lead whose asset is gone is not confirmed.
func LeadConfirmed(ctx context.Context, w DocumentLeadStore, entityID string, targets LeadTargets) bool {
	ent, err := w.FindEntityById(ctx, entityID)
	if err != nil || ent == nil {
		return false
	}
	return confirmedEntity(ctx, w, ent, entityEdges(ctx, w, ent), targets)
}

// confirmedEntity applies LeadConfirmed's rule to a lead's entity and its
// relations.
func confirmedEntity(ctx context.Context, w DocumentLeadStore, ent *dbt.Entity, edges []*dbt.Edge,
	targets LeadTargets) bool {
	if targets.Empty() {
		return len(edges) > 0 || otherSource(ctx, w, ent)
	}
	return len(edges) > 0 && tiedToTargets(ctx, w, ent, edges, targets)
}

// entityEdges returns the relations to and from an entity.
func entityEdges(ctx context.Context, w leadEdgeReader, ent *dbt.Entity) []*dbt.Edge {
	in, ierr := w.IncomingEdges(ctx, ent, time.Time{})
	out, oerr := w.OutgoingEdges(ctx, ent, time.Time{})
	return append(knownEdges(in, ierr), knownEdges(out, oerr)...)
}

// Footprint bounds: how far from the lead the walk goes, and how much of the
// branch it records.
const (
	footprintDepth   = 3
	footprintMaxSeen = 500
	footprintMaxIDs  = 100
)

// LeadFootprint is what the engine collected from a confirmed lead: the
// assets and relations created after the lead was given to the run that are
// reachable from it within a few hops, counted by type, with the first of
// their IDs. It is an approximation: something the engine found by another
// path in the same window is counted too.
type LeadFootprint struct {
	Assets    map[string]int `json:"assets"`
	Relations int            `json:"relations"`
	EntityIDs []string       `json:"entity_ids,omitempty"`
	Truncated bool           `json:"truncated,omitempty"`
}

// leadFootprint walks from a confirmed lead over the relations created since
// it was submitted.
func leadFootprint(ctx context.Context, w DocumentLeadStore, lead *dbt.Entity, since time.Time) LeadFootprint {
	fp := LeadFootprint{Assets: map[string]int{}}
	seen := map[string]bool{lead.ID: true}
	edgesSeen := map[string]bool{}
	frontier := []*dbt.Entity{lead}
	for depth := 0; depth < footprintDepth && len(frontier) > 0; depth++ {
		var next []*dbt.Entity
		for _, ent := range frontier {
			if ctx.Err() != nil {
				return fp
			}
			for _, e := range entityEdges(ctx, w, ent) {
				if e == nil || edgesSeen[e.ID] || (!e.CreatedAt.IsZero() && e.CreatedAt.Before(since)) {
					continue
				}
				edgesSeen[e.ID] = true
				fp.Relations++
				for _, end := range []*dbt.Entity{e.FromEntity, e.ToEntity} {
					if end == nil || seen[end.ID] {
						continue
					}
					if len(seen) >= footprintMaxSeen {
						fp.Truncated = true
						continue
					}
					seen[end.ID] = true
					other := end
					if other.Asset == nil {
						if found, err := w.FindEntityById(ctx, end.ID); err == nil && found != nil {
							other = found
						}
					}
					kind := "unknown"
					if other.Asset != nil {
						kind = string(other.Asset.AssetType())
					}
					fp.Assets[kind]++
					if len(fp.EntityIDs) < footprintMaxIDs {
						fp.EntityIDs = append(fp.EntityIDs, other.ID)
					}
					next = append(next, other)
				}
			}
		}
		frontier = next
	}
	return fp
}
