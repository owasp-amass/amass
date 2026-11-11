// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/platform"
)

// mergeTimeout bounds one merge or undo. Writes continue when the caller's
// context ends, so a merge is not left half done.
const mergeTimeout = 2 * time.Minute

const skippedBetween = "links the two merged organizations"

// MergeOrganizations moves the duplicate organization's properties and
// relationships onto the survivor and deletes the duplicate. Every moved
// relationship also carries the amass-ai source. The record lists what
// changed, including what the survivor already had, so
// UnmergeOrganizations removes only what the merge added. A merge that
// fails part way is rolled back.
func (a Adapter) MergeOrganizations(ctx context.Context, survivorID, duplicateID string,
	confidence int) (ai.MergeRecord, error) {
	rec := ai.MergeRecord{SurvivorID: survivorID, DuplicateID: duplicateID}
	if a.Repo == nil {
		return rec, errors.New("missing OAM repository")
	}
	if survivorID == duplicateID {
		return rec, errors.New("an organization cannot be merged into itself")
	}
	if confidence < 0 || confidence > 100 {
		return rec, fmt.Errorf("confidence %d is outside 0..100", confidence)
	}

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mergeTimeout)
	defer cancel()

	surv, err := a.entityOfType(wctx, survivorID, string(oam.Organization))
	if err != nil {
		return rec, err
	}
	dup, err := a.entityOfType(wctx, duplicateID, string(oam.Organization))
	if err != nil {
		return rec, err
	}

	if rec.DuplicateAsset, err = dup.Asset.JSON(); err != nil {
		return rec, err
	}
	if err := a.mergeEntityTags(wctx, surv, dup, &rec); err != nil {
		return rec, a.rollback(wctx, rec, err)
	}

	src := &general.SourceProperty{Source: ai.InferenceSource, Confidence: confidence}
	for _, outgoing := range []bool{true, false} {
		edges, err := a.edgesOf(wctx, dup, outgoing)
		if err != nil {
			return rec, a.rollback(wctx, rec, err)
		}

		for _, edge := range edges {
			m, err := a.moveEdge(wctx, surv, dup, edge, outgoing, src)
			rec.Edges = append(rec.Edges, m)
			if err != nil {
				return rec, a.rollback(wctx, rec, err)
			}
		}
	}

	if err := a.Repo.DeleteEntity(wctx, dup.ID); err != nil {
		return rec, a.rollback(wctx, rec, fmt.Errorf("delete organization %s: %w", dup.ID, err))
	}

	return rec, nil
}

func (a Adapter) edgesOf(ctx context.Context, ent *dbt.Entity, outgoing bool) ([]*dbt.Edge, error) {
	var edges []*dbt.Edge
	var err error
	if outgoing {
		edges, err = a.Repo.OutgoingEdges(ctx, ent, time.Time{})
	} else {
		edges, err = a.Repo.IncomingEdges(ctx, ent, time.Time{})
	}
	if err != nil && !emptyEdgeLookup(err) {
		return nil, err
	}

	return edges, nil
}

func (a Adapter) tagsOf(ctx context.Context, ent *dbt.Entity) ([]*dbt.EntityTag, error) {
	tags, err := a.Repo.FindEntityTags(ctx, ent, time.Time{})
	if err != nil && !emptyTagLookup(err) {
		return nil, err
	}

	return tags, nil
}

func (a Adapter) edgeTagsOf(ctx context.Context, edge *dbt.Edge) ([]*dbt.EdgeTag, error) {
	tags, err := a.Repo.FindEdgeTags(ctx, edge, time.Time{})
	if err != nil && !emptyTagLookup(err) {
		return nil, err
	}

	return tags, nil
}

// mergeEntityTags records the duplicate's properties and adds those the
// survivor lacks.
func (a Adapter) mergeEntityTags(ctx context.Context, surv, dup *dbt.Entity, rec *ai.MergeRecord) error {
	dupTags, err := a.tagsOf(ctx, dup)
	if err != nil {
		return err
	}
	survTags, err := a.tagsOf(ctx, surv)
	if err != nil {
		return err
	}

	var have []oam.Property
	for _, t := range survTags {
		if t != nil && t.Property != nil {
			have = append(have, t.Property)
		}
	}
	for _, t := range dupTags {
		if t == nil || t.Property == nil {
			continue
		}

		mt, err := mergedTag(t.Property)
		if err != nil {
			return err
		}
		rec.DuplicateTags = append(rec.DuplicateTags, mt)
		if hasProperty(have, t.Property) {
			continue
		}

		nt, err := a.Repo.CreateEntityProperty(ctx, surv, t.Property)
		if err != nil {
			return err
		}
		rec.SurvivorTagIDs = append(rec.SurvivorTagIDs, nt.ID)
		have = append(have, t.Property)
	}

	return nil
}

// moveEdge gives the survivor the duplicate's relationship, with its
// properties and the amass-ai source.
func (a Adapter) moveEdge(ctx context.Context, surv, dup *dbt.Entity, edge *dbt.Edge, outgoing bool,
	src oam.Property) (ai.MergedEdge, error) {
	m := ai.MergedEdge{ID: edge.ID, Outgoing: outgoing}
	if edge.Relation == nil || edge.FromEntity == nil || edge.ToEntity == nil {
		return m, fmt.Errorf("edge %s is incomplete", edge.ID)
	}

	other := edge.ToEntity
	if !outgoing {
		other = edge.FromEntity
	}

	var err error
	m.OtherID, m.Label, m.RelationType = other.ID, edge.Relation.Label(), string(edge.Relation.RelationType())
	if m.Relation, err = edge.Relation.JSON(); err != nil {
		return m, err
	}

	tags, err := a.edgeTagsOf(ctx, edge)
	if err != nil {
		return m, err
	}

	props := []oam.Property{}
	for _, t := range tags {
		if t == nil || t.Property == nil {
			continue
		}

		mt, err := mergedTag(t.Property)
		if err != nil {
			return m, err
		}
		m.Tags = append(m.Tags, mt)
		props = append(props, t.Property)
	}
	if other.ID == surv.ID {
		m.Skipped = skippedBetween
		return m, nil
	}

	target, existed, err := a.survivorEdge(ctx, surv, other, edge.Relation, outgoing)
	if err != nil {
		return m, err
	}
	m.SurvivorEdgeID, m.Created = target.ID, !existed

	var have []oam.Property
	if existed {
		existing, err := a.edgeTagsOf(ctx, target)
		if err != nil {
			return m, err
		}
		for _, t := range existing {
			if t != nil && t.Property != nil {
				have = append(have, t.Property)
			}
		}
	}
	for _, p := range append(props, src) {
		if hasProperty(have, p) {
			continue
		}

		nt, err := a.Repo.CreateEdgeProperty(ctx, target, p)
		if err != nil {
			return m, err
		}
		m.AddedTagIDs = append(m.AddedTagIDs, nt.ID)
		have = append(have, p)
	}

	return m, nil
}

// survivorEdge returns the survivor's matching relationship to other,
// creating it when the survivor has none.
func (a Adapter) survivorEdge(ctx context.Context, surv, other *dbt.Entity, rel oam.Relation,
	outgoing bool) (*dbt.Edge, bool, error) {
	existing, err := a.edgesOf(ctx, surv, outgoing)
	if err != nil {
		return nil, false, err
	}
	for _, e := range existing {
		if e == nil || e.Relation == nil || e.Relation.Label() != rel.Label() {
			continue
		}
		if (outgoing && e.ToEntity != nil && e.ToEntity.ID == other.ID) ||
			(!outgoing && e.FromEntity != nil && e.FromEntity.ID == other.ID) {
			return e, true, nil
		}
	}

	from, to := surv, other
	if !outgoing {
		from, to = other, surv
	}

	edge, err := a.Repo.CreateEdge(ctx, &dbt.Edge{Relation: rel, FromEntity: from, ToEntity: to})
	if err != nil {
		return nil, false, err
	} else if edge == nil {
		return nil, false, errors.New("failed to create the edge")
	}

	return edge, false, nil
}

// rollback removes what a failed merge added and returns err.
func (a Adapter) rollback(ctx context.Context, rec ai.MergeRecord, err error) error {
	if rerr := a.removeAdditions(ctx, rec); rerr != nil {
		return fmt.Errorf("%w; rolling back the merge also failed: %v", err, rerr)
	}

	return err
}

// removeAdditions deletes the properties and relationships a merge added
// to the survivor. A relationship the merge created is deleted only when
// nothing else has recorded it since.
func (a Adapter) removeAdditions(ctx context.Context, rec ai.MergeRecord) error {
	for _, m := range rec.Edges {
		if m.SurvivorEdgeID == "" {
			continue
		}

		edge, err := a.Repo.FindEdgeById(ctx, m.SurvivorEdgeID)
		if err != nil {
			// Already gone, such as when the other end was deleted.
			continue
		}

		tags, err := a.edgeTagsOf(ctx, edge)
		if err != nil {
			return err
		}

		others := 0
		for _, t := range tags {
			if t != nil && !slices.Contains(m.AddedTagIDs, t.ID) {
				others++
			}
		}
		if m.Created && others == 0 {
			if err := a.Repo.DeleteEdge(ctx, edge.ID); err != nil {
				return err
			}
			continue
		}
		for _, id := range m.AddedTagIDs {
			if err := a.Repo.DeleteEdgeTag(ctx, id); err != nil && !missing(err) {
				return err
			}
		}
	}
	for _, id := range rec.SurvivorTagIDs {
		if err := a.Repo.DeleteEntityTag(ctx, id); err != nil && !missing(err) {
			return err
		}
	}

	return nil
}

// UnmergeOrganizations undoes a merge: it removes what the merge added to
// the survivor and recreates the duplicate with its properties and the
// relationships whose other end still exists. It returns the restored
// organization's ID, which differs from the original.
func (a Adapter) UnmergeOrganizations(ctx context.Context, rec ai.MergeRecord) (string, error) {
	if a.Repo == nil {
		return "", errors.New("missing OAM repository")
	}

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mergeTimeout)
	defer cancel()

	surv, err := a.entityOfType(wctx, rec.SurvivorID, string(oam.Organization))
	if err != nil {
		return "", err
	}

	var o oamorg.Organization
	if err := json.Unmarshal(rec.DuplicateAsset, &o); err != nil {
		return "", fmt.Errorf("merge record organization: %w", err)
	}
	if err := a.removeAdditions(wctx, rec); err != nil {
		return "", err
	}

	dup, err := a.Repo.CreateAsset(wctx, &o)
	if err != nil {
		return "", err
	} else if dup == nil {
		return "", errors.New("failed to restore the organization")
	}

	for _, t := range rec.DuplicateTags {
		p, err := propertyFromTag(t)
		if err != nil {
			return dup.ID, err
		}
		if _, err := a.Repo.CreateEntityProperty(wctx, dup, p); err != nil {
			return dup.ID, err
		}
	}

	for _, m := range rec.Edges {
		other := surv
		if m.OtherID != rec.SurvivorID {
			if other, err = a.Repo.FindEntityById(wctx, m.OtherID); err != nil || other == nil {
				// The other end was deleted since the merge.
				continue
			}
		}

		rel, err := relationFromJSON(m.RelationType, m.Relation)
		if err != nil {
			return dup.ID, err
		}

		from, to := dup, other
		if !m.Outgoing {
			from, to = other, dup
		}

		edge, err := a.Repo.CreateEdge(wctx, &dbt.Edge{Relation: rel, FromEntity: from, ToEntity: to})
		if err != nil {
			return dup.ID, err
		}
		for _, t := range m.Tags {
			p, err := propertyFromTag(t)
			if err != nil {
				return dup.ID, err
			}
			if _, err := a.Repo.CreateEdgeProperty(wctx, edge, p); err != nil {
				return dup.ID, err
			}
		}
	}

	return dup.ID, nil
}

// missing reports whether err means the tag is already gone.
func missing(err error) bool {
	return err != nil && (emptyTagLookup(err) || strings.Contains(strings.ToLower(err.Error()), "not found"))
}

func hasProperty(have []oam.Property, p oam.Property) bool {
	for _, h := range have {
		if h.PropertyType() == p.PropertyType() && h.Name() == p.Name() && h.Value() == p.Value() {
			return true
		}
	}

	return false
}

func mergedTag(p oam.Property) (ai.MergedTag, error) {
	raw, err := p.JSON()
	if err != nil {
		return ai.MergedTag{}, err
	}

	return ai.MergedTag{Type: string(p.PropertyType()), Property: raw}, nil
}

func propertyFromTag(t ai.MergedTag) (oam.Property, error) {
	var p oam.Property
	switch oam.PropertyType(t.Type) {
	case oam.SimpleProperty:
		p = &general.SimpleProperty{}
	case oam.SourceProperty:
		p = &general.SourceProperty{}
	case oam.DNSRecordProperty:
		p = &oamdns.DNSRecordProperty{}
	case oam.VulnProperty:
		p = &platform.VulnProperty{}
	default:
		return nil, fmt.Errorf("unknown property type %q", t.Type)
	}

	if err := json.Unmarshal(t.Property, p); err != nil {
		return nil, fmt.Errorf("%s: %w", t.Type, err)
	}

	return p, nil
}

func relationFromJSON(t string, raw json.RawMessage) (oam.Relation, error) {
	var r oam.Relation
	switch oam.RelationType(t) {
	case oam.SimpleRelation:
		r = &general.SimpleRelation{}
	case oam.PortRelation:
		r = &general.PortRelation{}
	case oam.BasicDNSRelation:
		r = &oamdns.BasicDNSRelation{}
	case oam.PrefDNSRelation:
		r = &oamdns.PrefDNSRelation{}
	case oam.SRVDNSRelation:
		r = &oamdns.SRVDNSRelation{}
	default:
		return nil, fmt.Errorf("unknown relation type %q", t)
	}

	if err := json.Unmarshal(raw, r); err != nil {
		return nil, fmt.Errorf("%s: %w", t, err)
	}

	return r, nil
}
