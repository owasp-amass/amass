// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"errors"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// coKeyedGrouper is asset-db's repository.CoKeyedGrouper, declared here so an
// asset-db without it still builds; the duplicate sweep then falls back to an
// in-memory comparison.
type coKeyedGrouper interface {
	CoKeyedGroups(ctx context.Context, atype oam.AssetType, key dbt.CoKey, param string, maxGroup int, since time.Time) ([]dbt.CoKeyGroup, error)
}

var _ lens.CoKeyedGrouper = Adapter{}

// CoKeyedGroups implements lens.CoKeyedGrouper by delegating to the repository's
// database-side grouping. It maps the lens blocking-key kind to the asset-db
// key and, for a brand grouping, supplies the brand_key tag property name. A
// repository without the capability returns lens.ErrCoKeyedUnsupported so the
// sweep falls back.
func (a Adapter) CoKeyedGroups(ctx context.Context, assetType string, kind lens.CoKeyKind,
	maxGroup int, since time.Time) ([]lens.CoKeyGroup, error) {
	g, ok := a.Repo.(coKeyedGrouper)
	if !ok {
		return nil, lens.ErrCoKeyedUnsupported
	}

	var key dbt.CoKey
	var param string
	switch kind {
	case lens.CoKeyIdentifier:
		key = dbt.CoKeyIdentifier
	case lens.CoKeyContactRecord:
		key = dbt.CoKeyContactRecord
	case lens.CoKeyRegistration:
		key = dbt.CoKeyRegistration
	case lens.CoKeyBrand:
		key, param = dbt.CoKeyTag, lens.BrandKeyProperty
	case lens.CoKeyStreetAddress:
		key = dbt.CoKeyStreetAddress
	case lens.CoKeyPersonName:
		key, param = dbt.CoKeyTag, lens.PersonNameKeyProperty
	default:
		return nil, lens.ErrCoKeyedUnsupported
	}

	defer a.Stats.record("CoKeyedGroups", time.Now())

	groups, err := g.CoKeyedGroups(ctx, oam.AssetType(assetType), key, param, maxGroup, since)
	if err != nil {
		return nil, err
	}

	out := make([]lens.CoKeyGroup, 0, len(groups))
	for _, grp := range groups {
		out = append(out, lens.CoKeyGroup{Key: grp.Key, IDs: grp.IDs})
	}

	return out, nil
}

// EnsureBrandKeys materializes the brand_key tag (lens.BrandKey of the
// organization's name) for organizations that lack one, so the duplicate sweep
// can group by a shared brand in the database without a full scan. See
// ensureKeys for the bounded, incremental semantics. Placeholder organizations
// and names that reduce to an empty brand are skipped.
func (a Adapter) EnsureBrandKeys(ctx context.Context, limit int) (int, error) {
	defer a.Stats.record("EnsureBrandKeys", time.Now())

	return a.ensureKeys(ctx, oam.Organization, lens.BrandKeyProperty, limit, func(asset graph.Asset) string {
		if graph.IsPlaceholder(asset) || semantics.IsPlaceholderOrganization(graph.ContentString(asset, "name")) {
			return ""
		}
		if key := lens.BrandKey(graph.ContentString(asset, "name")); key != "" {
			return key
		}

		return lens.BrandKey(graph.ContentString(asset, "legal_name"))
	})
}

// EnsurePersonNameKeys materializes the person_name_key tag (lens.PersonNameKey
// of the Person's family name) for persons that lack one, so the person
// -duplicate sweep can group by a shared family name in the database without a
// full scan. See ensureKeys for the bounded, incremental semantics.
func (a Adapter) EnsurePersonNameKeys(ctx context.Context, limit int) (int, error) {
	defer a.Stats.record("EnsurePersonNameKeys", time.Now())

	return a.ensureKeys(ctx, oam.Person, lens.PersonNameKeyProperty, limit, func(asset graph.Asset) string {
		return lens.PersonNameKey(graph.ContentString(asset, "family_name"))
	})
}

// ensureKeys materializes a derived key tag (property) for entities of atype
// that lack it. keyFor computes the key for one asset ("" to skip it). It writes
// at most limit tags per call and scans at most keyBackfillScanCap entities
// (paged through the keyset entity pager), so it is a bounded, incremental
// backfill: repeated calls bring the store current without loading the whole
// type. It returns the number of tags written. A repository without the entity
// pager is a no-op (grouping then uses whatever keys are already stored).
func (a Adapter) ensureKeys(ctx context.Context, atype oam.AssetType, property string, limit int,
	keyFor func(graph.Asset) string) (int, error) {
	if a.Repo == nil {
		return 0, errors.New("missing OAM repository")
	}
	pager, ok := a.Repo.(entityPager)
	if !ok {
		return 0, nil
	}
	if limit <= 0 {
		limit = keyBackfillDefault
	}

	var written, scanned int
	var after *dbt.EntityCursor
	for scanned < keyBackfillScanCap && written < limit {
		n := keyBackfillPageSize
		if rem := keyBackfillScanCap - scanned; rem < n {
			n = rem
		}

		ents, next, err := pager.EntitiesPage(ctx, atype, time.Time{}, after, n)
		if err != nil {
			return written, err
		}

		for _, e := range ents {
			scanned++
			if written >= limit {
				break
			}
			if err := ctx.Err(); err != nil {
				return written, err
			}

			asset, err := convert(e)
			if err != nil {
				continue
			}

			key := keyFor(asset)
			if key == "" {
				continue
			}

			// Skip entities already carrying the tag so repeated calls do not
			// rewrite them and the limit advances onto untagged entities.
			// FindEntityTags reports an error when the entity has no matching
			// tag; filtered by this property name, that only means the key is
			// absent, so fall through and write it (the tag's uniqueness makes a
			// repeat write idempotent regardless).
			if tags, err := a.Repo.FindEntityTags(ctx, e, time.Time{}, property); err == nil &&
				keyTagPresent(tags, property, key) {
				continue
			}

			if _, err := a.Repo.CreateEntityProperty(ctx, e,
				&oamgen.SimpleProperty{PropertyName: property, PropertyValue: key}); err != nil {
				return written, err
			}
			written++
		}

		if next == nil {
			break
		}
		after = next
	}

	return written, nil
}

// entityPager is asset-db's repository.EntityPager, declared here so an
// asset-db without it still builds; the audit sweeps then fall back to a single
// capped load.
type entityPager interface {
	EntitiesPage(ctx context.Context, atype oam.AssetType, since time.Time,
		after *dbt.EntityCursor, limit int) ([]*dbt.Entity, *dbt.EntityCursor, error)
}

var _ lens.TypePager = Adapter{}

// PageAssets implements lens.TypePager by delegating to the repository's keyset
// entity pager. The opaque cursor is the entity id. A repository without the
// capability returns lens.ErrTypePagingUnsupported so the audit falls back.
func (a Adapter) PageAssets(ctx context.Context, assetType, after string, limit int) ([]graph.Asset, string, error) {
	p, ok := a.Repo.(entityPager)
	if !ok {
		return nil, "", lens.ErrTypePagingUnsupported
	}

	defer a.Stats.record("PageAssets", time.Now())

	var cur *dbt.EntityCursor
	if after != "" {
		cur = &dbt.EntityCursor{EntityID: after}
	}

	ents, next, err := p.EntitiesPage(ctx, oam.AssetType(assetType), time.Time{}, cur, limit)
	if err != nil {
		return nil, "", err
	}

	out := make([]graph.Asset, 0, len(ents))
	for _, e := range ents {
		asset, err := convert(e)
		if err != nil {
			continue
		}

		out = append(out, asset)
	}

	var nextStr string
	if next != nil {
		nextStr = next.EntityID
	}

	return out, nextStr, nil
}

// keyTagPresent reports whether tags already carry the property's key value.
func keyTagPresent(tags []*dbt.EntityTag, property, key string) bool {
	for _, t := range tags {
		if t == nil || t.Property == nil {
			continue
		}
		if sp, ok := t.Property.(*oamgen.SimpleProperty); ok &&
			sp.PropertyName == property && sp.PropertyValue == key {
			return true
		}
	}

	return false
}

const (
	// keyBackfillDefault is the number of key tags one call writes when the
	// caller names no limit.
	keyBackfillDefault = 500
	// keyBackfillPageSize is the entity pager page size the backfill reads.
	keyBackfillPageSize = 1000
	// keyBackfillScanCap is the hard ceiling on entities scanned in one call.
	keyBackfillScanCap = 5000
)
