// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/ai"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// CorrectIdentity removes a contradicted legal identity: each listed
// relationship loses its enrichment-source tags and is deleted when no
// other source recorded it, and the organization's legal fields are
// cleared. The record holds what changed, so UndoIdentityCorrection can
// restore it.
func (a Adapter) CorrectIdentity(ctx context.Context, c ai.IdentityConflict) (ai.IdentityRecord, error) {
	rec := ai.IdentityRecord{OrgID: c.OrgID}
	if a.Repo == nil {
		return rec, errors.New("missing OAM repository")
	}

	r, ok := a.Repo.(assetReplacer)
	if !ok {
		return rec, errors.New("this Asset Database cannot clear an organization's fields")
	}

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mergeTimeout)
	defer cancel()

	ent, err := a.entityOfType(wctx, c.OrgID, string(oam.Organization))
	if err != nil {
		return rec, err
	}
	o, ok := ent.Asset.(*oamorg.Organization)
	if !ok {
		return rec, errors.New("not an organization")
	}
	// The identity must still be the one the proposal reviewed.
	if !strings.EqualFold(o.LegalName, c.LegalName) || !strings.EqualFold(o.Jurisdiction, c.Jurisdiction) {
		return rec, fmt.Errorf("the legal identity of %s changed since the proposal", c.Organization)
	}
	if rec.Before, err = o.JSON(); err != nil {
		return rec, err
	}

	for _, id := range c.EdgeIDs {
		ce, err := a.untagEnrichment(wctx, ent, id)
		if err != nil {
			return rec, a.undoIdentityEdges(wctx, rec, err)
		}
		if ce != nil {
			rec.Edges = append(rec.Edges, *ce)
		}
	}

	next := *o
	for _, f := range c.Fields {
		switch f {
		case "legal_name":
			next.LegalName = ""
		case "jurisdiction":
			next.Jurisdiction = ""
		case "registration_id":
			next.RegistrationID = ""
		case "founding_date":
			next.FoundingDate = ""
		}
	}
	if _, err := r.ReplaceAsset(wctx, &next); err != nil {
		return rec, a.undoIdentityEdges(wctx, rec, err)
	}

	return rec, nil
}

// untagEnrichment removes the enrichment sources from one relationship and
// deletes it when nothing else recorded it. It returns nil when the
// relationship is gone or carries no enrichment source.
func (a Adapter) untagEnrichment(ctx context.Context, org *dbt.Entity, edgeID string) (*ai.CorrectedEdge, error) {
	edge, err := a.Repo.FindEdgeById(ctx, edgeID)
	if err != nil || edge == nil || edge.Relation == nil || edge.FromEntity == nil || edge.ToEntity == nil {
		return nil, nil
	}

	outgoing := edge.FromEntity.ID == org.ID
	if !outgoing && edge.ToEntity.ID != org.ID {
		return nil, fmt.Errorf("edge %s does not belong to organization %s", edgeID, org.ID)
	}

	ce := ai.CorrectedEdge{MergedEdge: ai.MergedEdge{ID: edge.ID, Outgoing: outgoing,
		Label: edge.Relation.Label(), RelationType: string(edge.Relation.RelationType())}}
	ce.OtherID = edge.ToEntity.ID
	if !outgoing {
		ce.OtherID = edge.FromEntity.ID
	}
	if ce.Relation, err = edge.Relation.JSON(); err != nil {
		return nil, err
	}

	tags, err := a.edgeTagsOf(ctx, edge)
	if err != nil {
		return nil, err
	}

	var enrich []*dbt.EdgeTag
	others := 0
	for _, t := range tags {
		if t == nil || t.Property == nil {
			continue
		}

		mt, err := mergedTag(t.Property)
		if err != nil {
			return nil, err
		}
		ce.Tags = append(ce.Tags, mt)
		if ai.IsEnrichmentSource(source(t.Property)) {
			enrich = append(enrich, t)
			ce.RemovedTags = append(ce.RemovedTags, mt)
		} else {
			others++
		}
	}
	if len(enrich) == 0 {
		return nil, nil
	}

	if others == 0 {
		if err := a.Repo.DeleteEdge(ctx, edge.ID); err != nil {
			return nil, err
		}
		ce.Deleted = true
		return &ce, nil
	}
	for _, t := range enrich {
		if err := a.Repo.DeleteEdgeTag(ctx, t.ID); err != nil && !missing(err) {
			return nil, err
		}
	}

	return &ce, nil
}

// undoIdentityEdges restores the relationships a failed correction touched
// and returns err.
func (a Adapter) undoIdentityEdges(ctx context.Context, rec ai.IdentityRecord, err error) error {
	if rerr := a.restoreIdentityEdges(ctx, rec); rerr != nil {
		return fmt.Errorf("%w; restoring the relationships also failed: %v", err, rerr)
	}

	return err
}

func (a Adapter) restoreIdentityEdges(ctx context.Context, rec ai.IdentityRecord) error {
	org, err := a.entityOfType(ctx, rec.OrgID, string(oam.Organization))
	if err != nil {
		return err
	}

	for _, ce := range rec.Edges {
		var edge *dbt.Edge
		if ce.Deleted {
			other, err := a.Repo.FindEntityById(ctx, ce.OtherID)
			if err != nil || other == nil {
				// The other end was deleted since the correction.
				continue
			}

			rel, err := relationFromJSON(ce.RelationType, ce.Relation)
			if err != nil {
				return err
			}

			from, to := org, other
			if !ce.Outgoing {
				from, to = other, org
			}
			if edge, err = a.Repo.CreateEdge(ctx, &dbt.Edge{Relation: rel, FromEntity: from, ToEntity: to}); err != nil {
				return err
			}
		} else if edge, err = a.Repo.FindEdgeById(ctx, ce.ID); err != nil || edge == nil {
			continue
		}

		have, err := a.edgeTagsOf(ctx, edge)
		if err != nil {
			return err
		}
		var props []oam.Property
		for _, t := range have {
			if t != nil && t.Property != nil {
				props = append(props, t.Property)
			}
		}

		restore := ce.RemovedTags
		if ce.Deleted {
			restore = ce.Tags
		}
		for _, mt := range restore {
			p, err := propertyFromTag(mt)
			if err != nil {
				return err
			}
			if hasProperty(props, p) {
				continue
			}
			if _, err := a.Repo.CreateEdgeProperty(ctx, edge, p); err != nil {
				return err
			}
		}
	}

	return nil
}

// UndoIdentityCorrection restores the organization's legal fields and the
// relationships and sources the correction removed.
func (a Adapter) UndoIdentityCorrection(ctx context.Context, rec ai.IdentityRecord) error {
	if a.Repo == nil {
		return errors.New("missing OAM repository")
	}

	r, ok := a.Repo.(assetReplacer)
	if !ok {
		return errors.New("this Asset Database cannot restore an organization's fields")
	}

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mergeTimeout)
	defer cancel()

	var before oamorg.Organization
	if err := json.Unmarshal(rec.Before, &before); err != nil {
		return fmt.Errorf("correction record organization: %w", err)
	}

	ent, err := a.entityOfType(wctx, rec.OrgID, string(oam.Organization))
	if err != nil {
		return err
	}
	cur, ok := ent.Asset.(*oamorg.Organization)
	if !ok {
		return errors.New("not an organization")
	}

	// Restore only the legal fields; anything else changed since is kept.
	next := *cur
	next.LegalName, next.Jurisdiction = before.LegalName, before.Jurisdiction
	next.RegistrationID, next.FoundingDate = before.RegistrationID, before.FoundingDate
	if _, err := r.ReplaceAsset(wctx, &next); err != nil {
		return err
	}

	return a.restoreIdentityEdges(wctx, rec)
}
