// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// BrandKeyProperty is the entity-tag property name under which an
// organization's brand key is materialized. Grouping organizations by a shared
// brand needs the brandName form of the name, which the database cannot
// compute, so the backfill writes it as this tag and the duplicate sweep groups
// by it (CoKeyBrand) without a full scan.
const BrandKeyProperty = "brand_key"

// PersonNameKeyProperty is the entity-tag property name under which a Person's
// family-name key is materialized, so the person-duplicate sweep groups persons
// by a shared family name (CoKeyPersonName) in the database. The key is the
// normalized family name, which the database cannot compute.
const PersonNameKeyProperty = "person_name_key"

// CoKeyKind names a blocking key by which the database groups organizations as
// duplicate candidates without loading the whole type into memory.
type CoKeyKind int

const (
	// CoKeyIdentifier groups organizations sharing an Identifier (an "id" edge).
	CoKeyIdentifier CoKeyKind = iota
	// CoKeyContactRecord groups organizations sharing a ContactRecord.
	CoKeyContactRecord
	// CoKeyRegistration groups organizations sharing a normalized
	// (jurisdiction, registration_id).
	CoKeyRegistration
	// CoKeyBrand groups organizations sharing a brand_key tag.
	CoKeyBrand
	// CoKeyLocation groups organizations sharing a Location (an address edge).
	CoKeyLocation
	// CoKeyPersonName groups persons sharing a person_name_key tag.
	CoKeyPersonName
)

// CoKeyGroup is a set of organization asset ids that share one blocking key.
// Key is the shared value, kept for diagnostics.
type CoKeyGroup struct {
	Key string
	IDs []string
}

// CoKeyedGrouper is the optional graph capability that generates
// duplicate-candidate groups in the database: the organizations that already
// share a blocking key, in groups of 2..maxGroup members (a key shared by more
// than maxGroup is too common to discriminate and is dropped). A repository
// without it makes the sweep fall back to loading and pairing organizations in
// memory.
type CoKeyedGrouper interface {
	CoKeyedGroups(ctx context.Context, assetType string, kind CoKeyKind, maxGroup int, since time.Time) ([]CoKeyGroup, error)
}

// ErrCoKeyedUnsupported reports a repository without database-side co-keyed
// grouping; the sweep falls back to an in-memory comparison.
var ErrCoKeyedUnsupported = errors.New("the repository does not support co-keyed grouping")

// TypePager is the optional graph capability that reads the assets of one type
// a bounded page at a time (keyset by id), so a per-asset audit sweep (identity,
// person-named) scales without an arbitrary load cap. A repository without it
// makes the audit fall back to a single capped load.
type TypePager interface {
	// PageAssets returns up to limit assets of assetType after the opaque
	// cursor (empty starts at the first). next is "" on the last page;
	// otherwise pass it back unchanged for the following page.
	PageAssets(ctx context.Context, assetType, after string, limit int) (assets []graph.Asset, next string, err error)
}

// ErrTypePagingUnsupported reports a repository without database-side type
// paging; the audit falls back to a single capped load.
var ErrTypePagingUnsupported = errors.New("the repository does not support type paging")

// BrandKey returns the brand key for an organization name: its brandName form
// (lower-cased, without surrounding punctuation or a trailing legal form), or
// "" when the name reduces to nothing. It is exported so the brand-key backfill
// stores exactly the value the duplicate sweep groups by.
func BrandKey(name string) string {
	return brandName(name)
}

// PersonNameKey returns the family-name key for a Person: the normalized family
// name the person-duplicate sweep buckets by, or "" when it reduces to nothing.
// It is exported so the person-name-key backfill stores exactly the value the
// sweep groups by.
func PersonNameKey(familyName string) string {
	return personNorm(familyName)
}

// coKeyedCohortIDs returns the union of the entity ids of assetType that share
// any of the given blocking keys, grouped in the database. Each group is capped
// at maxGroup members (keys shared by more are dropped as non-discriminating);
// the union is capped at maxIDs, and the bool reports whether that cap was hit.
func coKeyedCohortIDs(ctx context.Context, cg CoKeyedGrouper, assetType string, kinds []CoKeyKind,
	maxGroup, maxIDs int) ([]string, bool, error) {
	seen := map[string]bool{}
	var ids []string
	for _, kind := range kinds {
		groups, err := cg.CoKeyedGroups(ctx, assetType, kind, maxGroup, time.Time{})
		if err != nil {
			return nil, false, err
		}
		for _, g := range groups {
			for _, id := range g.IDs {
				if seen[id] {
					continue
				}

				seen[id] = true
				ids = append(ids, id)
				if len(ids) >= maxIDs {
					return ids, true, nil
				}
			}
		}
	}

	return ids, false, nil
}

// forEachTypeAsset calls fn for every asset of assetType, read through tp one
// bounded page at a time. fn returns stop=true to end the walk early (e.g. a
// read budget was spent). pageSize bounds one page.
func forEachTypeAsset(ctx context.Context, tp TypePager, assetType string, pageSize int,
	fn func(graph.Asset) (stop bool, err error)) error {
	after := ""
	for {
		assets, next, err := tp.PageAssets(ctx, assetType, after, pageSize)
		if err != nil {
			return err
		}
		for _, a := range assets {
			stop, err := fn(a)
			if err != nil {
				return err
			}
			if stop {
				return nil
			}
		}
		if next == "" {
			return nil
		}

		after = next
	}
}

// walkType calls fn for each asset of assetType, for the per-asset audit sweeps.
// When g supports TypePager it pages through the whole type with no cap;
// otherwise it loads one capped page and reports capped=true when the cap was
// hit. pageSize bounds a page; capLimit bounds the fallback load. fn returns
// stop=true to end early (e.g. a read budget was spent).
func walkType(ctx context.Context, g graph.Graph, assetType string, pageSize, capLimit int,
	fn func(graph.Asset) (stop bool, err error)) (capped bool, err error) {
	if tp, ok := g.(TypePager); ok {
		err := forEachTypeAsset(ctx, tp, assetType, pageSize, fn)
		if err == nil {
			return false, nil
		}
		if !errors.Is(err, ErrTypePagingUnsupported) {
			return false, err
		}
		// The repository lacks database-side paging; fall back to the load.
	}

	assets, err := g.FindAssets(ctx, assetType, time.Time{}, capLimit+1)
	if err != nil {
		return false, err
	}
	if len(assets) > capLimit {
		assets = assets[:capLimit]
		capped = true
	}

	for _, a := range assets {
		stop, ferr := fn(a)
		if ferr != nil {
			return capped, ferr
		}
		if stop {
			break
		}
	}

	return capped, nil
}

// typePageSize is the page size the per-asset audit sweeps read through a
// TypePager.
const typePageSize = 1000
