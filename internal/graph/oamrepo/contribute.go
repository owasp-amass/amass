// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/owasp-amass/amass/v5/engine/api/client"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/review"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

var _ review.ContributionWriter = Adapter{}

// contributionConfidence is the source confidence of an item that names
// none.
const contributionConfidence = 50

// WriteContribution writes each item into the Asset Database, an asset,
// relation or property checked against the OAM schema, and tags each asset
// and relation with the contribution's source. It returns what it wrote,
// also when it stops at an item it cannot write, so the caller can undo it.
func (a Adapter) WriteContribution(ctx context.Context, source string,
	items []review.ContributedItem) (review.ContributionWrite, error) {
	var w review.ContributionWrite
	if a.Repo == nil {
		return w, errors.New("missing repository")
	}

	assets := make([]*dbt.Entity, len(items))
	for i, it := range items {
		conf := it.Confidence
		if conf == 0 {
			conf = contributionConfidence
		}
		src := &oamgen.SourceProperty{Source: source, Confidence: conf}

		var err error
		switch it.Kind {
		case review.ContributedAsset:
			assets[i], err = a.writeContributedAsset(ctx, &w, it, src)
		case review.ContributedRelation:
			err = a.writeContributedRelation(ctx, &w, it, assets, src)
		case review.ContributedProperty:
			err = a.writeContributedProperty(ctx, &w, it, assets)
		default:
			err = fmt.Errorf("unknown kind %q", it.Kind)
		}
		if err != nil {
			return w, fmt.Errorf("item %d (%s): %w", i, it.Describe(), err)
		}
	}
	return w, nil
}

// ContributedAsset is an asset item's OAM asset: its type, its fields (none
// the type does not have) and a key.
func ContributedAsset(it review.ContributedItem) (oam.Asset, error) {
	asset, ok := client.NewAsset(oam.AssetType(it.AssetType))
	if !ok {
		return nil, fmt.Errorf("%q is not an OAM asset type", it.AssetType)
	}
	if err := decodeFields(it.Fields, asset); err != nil {
		return nil, err
	}
	if asset.Key() == "" {
		return nil, fmt.Errorf("the %s has no key field set", it.AssetType)
	}
	return asset, nil
}

func (a Adapter) writeContributedAsset(ctx context.Context, w *review.ContributionWrite, it review.ContributedItem,
	src oam.Property) (*dbt.Entity, error) {
	asset, err := ContributedAsset(it)
	if err != nil {
		return nil, err
	}

	ent, err := a.Repo.CreateAsset(ctx, asset)
	if err != nil || ent == nil {
		return nil, fmt.Errorf("store the %s: %w", it.AssetType, err)
	}
	w.EntityIDs = append(w.EntityIDs, ent.ID)
	return ent, a.tagEntity(ctx, w, ent, src)
}

func (a Adapter) writeContributedRelation(ctx context.Context, w *review.ContributionWrite, it review.ContributedItem,
	assets []*dbt.Entity, src oam.Property) error {
	from, err := a.contributedRef(ctx, it.From, assets)
	if err != nil {
		return fmt.Errorf("from: %w", err)
	}
	to, err := a.contributedRef(ctx, it.To, assets)
	if err != nil {
		return fmt.Errorf("to: %w", err)
	}

	rel, err := contributedRelation(it)
	if err != nil {
		return err
	}
	if !oam.ValidRelationship(from.Asset.AssetType(), it.Label, rel.RelationType(), to.Asset.AssetType()) {
		return fmt.Errorf("%s -%s-> %s is not an OAM relationship", from.Asset.AssetType(), it.Label,
			to.Asset.AssetType())
	}

	edge, err := a.Repo.CreateEdge(ctx, &dbt.Edge{Relation: rel, FromEntity: from, ToEntity: to})
	if err != nil || edge == nil || edge.ID == "" {
		return fmt.Errorf("store the relation: %w", err)
	}
	w.EdgeIDs = append(w.EdgeIDs, edge.ID)

	tags, err := a.Repo.FindEdgeTags(ctx, edge, time.Time{}, src.Name())
	existed := err == nil && len(tags) > 0
	tag, err := a.Repo.CreateEdgeProperty(ctx, edge, src)
	if err != nil || tag == nil {
		return fmt.Errorf("tag the relation: %w", err)
	}
	w.Tags = append(w.Tags, review.ContributionTag{ID: tag.ID, OnEdge: true, Owner: edge.ID, Existed: existed})
	return nil
}

func (a Adapter) writeContributedProperty(ctx context.Context, w *review.ContributionWrite, it review.ContributedItem,
	assets []*dbt.Entity) error {
	target, err := a.contributedRef(ctx, it.Target, assets)
	if err != nil {
		return fmt.Errorf("target: %w", err)
	}

	var prop oam.Property
	switch it.PropertyType {
	case "", string(oam.SimpleProperty):
		prop = &oamgen.SimpleProperty{}
	case string(oam.DNSRecordProperty):
		prop = &oamdns.DNSRecordProperty{}
	case string(oam.VulnProperty):
		prop = &oamplat.VulnProperty{}
	default:
		return fmt.Errorf("%q is not a property an assistant can contribute", it.PropertyType)
	}
	if err := decodeFields(it.Fields, prop); err != nil {
		return err
	}
	if prop.Name() == "" {
		return errors.New("the property has no name")
	}

	return a.tagEntity(ctx, w, target, prop)
}

// tagEntity adds p to ent, noting whether the same property was there.
func (a Adapter) tagEntity(ctx context.Context, w *review.ContributionWrite, ent *dbt.Entity, p oam.Property) error {
	existed := false
	if tags, err := a.Repo.FindEntityTags(ctx, ent, time.Time{}, p.Name()); err == nil {
		for _, t := range tags {
			if t.Property != nil && t.Property.PropertyType() == p.PropertyType() && t.Property.Value() == p.Value() {
				existed = true
			}
		}
	}

	tag, err := a.Repo.CreateEntityProperty(ctx, ent, p)
	if err != nil || tag == nil {
		return fmt.Errorf("store the %s: %w", p.PropertyType(), err)
	}
	w.Tags = append(w.Tags, review.ContributionTag{ID: tag.ID, Owner: ent.ID, Existed: existed})
	return nil
}

// contributedRef is the entity a reference names: an asset item written
// earlier in the contribution, or the one stored asset with the field.
func (a Adapter) contributedRef(ctx context.Context, r *review.AssetRef, assets []*dbt.Entity) (*dbt.Entity, error) {
	if r == nil {
		return nil, errors.New("names no asset")
	}
	if r.Item != nil {
		if *r.Item < 0 || *r.Item >= len(assets) || assets[*r.Item] == nil {
			return nil, fmt.Errorf("item %d is not an earlier asset item", *r.Item)
		}
		return assets[*r.Item], nil
	}

	res, err := a.ResolveAsset(ctx, graph.AssetSelector{Type: r.Type, Field: r.Field, Value: r.Value}, 2)
	if err != nil {
		return nil, err
	}
	switch {
	case len(res.Candidates) == 0:
		return nil, fmt.Errorf("no stored %s has %s %q", r.Type, r.Field, r.Value)
	case len(res.Candidates) > 1 || res.Truncated:
		return nil, fmt.Errorf("more than one stored %s has %s %q", r.Type, r.Field, r.Value)
	}
	return a.Repo.FindEntityById(ctx, res.Candidates[0].Asset.ID)
}

// contributedRelation builds an item's relation of its type, labeled.
func contributedRelation(it review.ContributedItem) (oam.Relation, error) {
	label := map[string]any{"label": it.Label}
	for k, v := range it.Fields {
		label[k] = v
	}

	var rel oam.Relation
	switch it.RelationType {
	case "", string(oam.SimpleRelation):
		rel = &oamgen.SimpleRelation{}
	case string(oam.BasicDNSRelation):
		rel = &oamdns.BasicDNSRelation{}
	case string(oam.PrefDNSRelation):
		rel = &oamdns.PrefDNSRelation{}
	case string(oam.SRVDNSRelation):
		rel = &oamdns.SRVDNSRelation{}
	case string(oam.PortRelation):
		rel = &oamgen.PortRelation{}
	default:
		return nil, fmt.Errorf("%q is not an OAM relation type", it.RelationType)
	}
	if err := decodeFields(label, rel); err != nil {
		return nil, err
	}
	return rel, nil
}

// decodeFields fills v from an item's fields, refusing a field v does not
// have.
func decodeFields(fields map[string]any, v any) error {
	raw, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("fields: %w", err)
	}
	return nil
}

// UndoContribution removes the properties the contribution added (not those
// that were there already), then each edge and entity it wrote that no
// other source records: an edge with no source left, an entity with no
// source and no edges left. What a collector also observed stays.
func (a Adapter) UndoContribution(ctx context.Context, source string, w review.ContributionWrite) error {
	if a.Repo == nil {
		return errors.New("missing repository")
	}

	for _, t := range w.Tags {
		if t.Existed {
			continue
		}
		var err error
		if t.OnEdge {
			err = a.Repo.DeleteEdgeTag(ctx, t.ID)
		} else {
			err = a.Repo.DeleteEntityTag(ctx, t.ID)
		}
		if err != nil && !missing(err) {
			return fmt.Errorf("remove tag %s: %w", t.ID, err)
		}
	}

	for _, id := range w.EdgeIDs {
		edge, err := a.Repo.FindEdgeById(ctx, id)
		if err != nil || edge == nil {
			continue
		}
		tags, err := a.Repo.FindEdgeTags(ctx, edge, time.Time{})
		if (err != nil && !emptyTagLookup(err)) || hasSource(edgeProperties(tags)) {
			continue
		}
		if err := a.Repo.DeleteEdge(ctx, id); err != nil && !missing(err) {
			return fmt.Errorf("remove relation %s: %w", id, err)
		}
	}

	for i := len(w.EntityIDs) - 1; i >= 0; i-- {
		ent, err := a.Repo.FindEntityById(ctx, w.EntityIDs[i])
		if err != nil || ent == nil {
			continue
		}
		tags, err := a.Repo.FindEntityTags(ctx, ent, time.Time{})
		if (err != nil && !emptyTagLookup(err)) || hasSource(entityProperties(tags)) {
			continue
		}
		if in, err := a.Repo.IncomingEdges(ctx, ent, time.Time{}); (err != nil && !emptyEdgeLookup(err)) ||
			len(in) > 0 {
			continue
		}
		if out, err := a.Repo.OutgoingEdges(ctx, ent, time.Time{}); (err != nil && !emptyEdgeLookup(err)) ||
			len(out) > 0 {
			continue
		}
		if err := a.Repo.DeleteEntity(ctx, ent.ID); err != nil && !missing(err) {
			return fmt.Errorf("remove asset %s: %w", ent.ID, err)
		}
	}
	return nil
}

func entityProperties(tags []*dbt.EntityTag) []oam.Property {
	out := make([]oam.Property, 0, len(tags))
	for _, t := range tags {
		if t != nil {
			out = append(out, t.Property)
		}
	}
	return out
}

func edgeProperties(tags []*dbt.EdgeTag) []oam.Property {
	out := make([]oam.Property, 0, len(tags))
	for _, t := range tags {
		if t != nil {
			out = append(out, t.Property)
		}
	}
	return out
}

// hasSource reports whether any of the properties is a source.
func hasSource(props []oam.Property) bool {
	for _, p := range props {
		if p != nil && p.PropertyType() == oam.SourceProperty {
			return true
		}
	}
	return false
}
