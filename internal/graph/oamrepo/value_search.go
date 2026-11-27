// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// valueFinder is the paged half of asset-db's repository.ValueFinder; a
// repository without it gives no value searches, and the signals that need
// them are skipped.
type valueFinder interface {
	FindEntitiesByTagValueAfter(ctx context.Context, atype oam.AssetType, name, value string, contains bool,
		since time.Time, after string, limit int) ([]*dbt.Entity, bool, error)
	FindEntitiesByAttributeAfter(ctx context.Context, atype oam.AssetType, key, value string, contains bool,
		since time.Time, after string, limit int) ([]*dbt.Entity, bool, error)
}

// valuePage is the most matches one value search returns (asset-db's
// limit); a search for more reads page after page.
const valuePage = 500

// valuePages reads a value search page by page, each starting after the
// last entity of the one before: up to limit matches, or every match when
// limit is 0, and whether more matched than were read.
func valuePages(limit int, read func(after string, n int) ([]*dbt.Entity, bool, error)) ([]*dbt.Entity, bool, error) {
	var out []*dbt.Entity
	after := ""
	for {
		n := valuePage
		if limit > 0 {
			n = min(n, limit-len(out))
		}
		ents, more, err := read(after, n)
		if err != nil {
			return nil, false, err
		}
		out = append(out, ents...)
		if !more || len(ents) == 0 {
			return out, false, nil
		}
		if limit > 0 && len(out) >= limit {
			return out, true, nil
		}
		after = ents[len(ents)-1].ID
	}
}

var _ lens.ValueSearcher = Adapter{}

// FindByTagValue implements ai.ValueSearcher.
func (a Adapter) FindByTagValue(ctx context.Context, assetType, name, value string, contains bool, limit int) ([]graph.Asset, bool, error) {
	vf, ok := a.Repo.(valueFinder)
	if !ok {
		return nil, false, lens.ErrValueSearchUnsupported
	}
	// searching withheld document text by value would reveal it piece by piece
	if a.WithholdDocumentText && graph.IsDocumentTextProperty(name) {
		return nil, false, nil
	}

	ents, more, err := valuePages(limit, func(after string, n int) ([]*dbt.Entity, bool, error) {
		return vf.FindEntitiesByTagValueAfter(ctx, oam.AssetType(assetType), name, value, contains, time.Time{}, after, n)
	})
	if err != nil {
		return nil, false, err
	}

	return convertAll(ents, more)
}

// FindByAttribute implements ai.ValueSearcher.
func (a Adapter) FindByAttribute(ctx context.Context, assetType, key, value string, contains bool, limit int) ([]graph.Asset, bool, error) {
	vf, ok := a.Repo.(valueFinder)
	if !ok {
		return nil, false, lens.ErrValueSearchUnsupported
	}

	ents, more, err := valuePages(limit, func(after string, n int) ([]*dbt.Entity, bool, error) {
		return vf.FindEntitiesByAttributeAfter(ctx, oam.AssetType(assetType), key, value, contains, time.Time{}, after, n)
	})
	if err != nil {
		return nil, false, err
	}

	return convertAll(ents, more)
}

func convertAll(ents []*dbt.Entity, more bool) ([]graph.Asset, bool, error) {
	out := make([]graph.Asset, 0, len(ents))
	for _, e := range ents {
		a, err := convert(e)
		if err != nil {
			return nil, false, err
		}

		out = append(out, a)
	}

	return out, more, nil
}
