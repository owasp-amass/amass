// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// valueFinder is asset-db's repository.ValueFinder, declared here so an
// asset-db without it still builds; the signals that need it are skipped.
type valueFinder interface {
	FindEntitiesByTagValue(ctx context.Context, atype oam.AssetType, name, value string, contains bool, since time.Time, limit int) ([]*dbt.Entity, bool, error)
	FindEntitiesByAttribute(ctx context.Context, atype oam.AssetType, key, value string, since time.Time, limit int) ([]*dbt.Entity, bool, error)
}

var _ ai.ValueSearcher = Adapter{}

// FindByTagValue implements ai.ValueSearcher.
func (a Adapter) FindByTagValue(ctx context.Context, assetType, name, value string, contains bool, limit int) ([]ai.Asset, bool, error) {
	vf, ok := a.Repo.(valueFinder)
	if !ok {
		return nil, false, ai.ErrValueSearchUnsupported
	}

	ents, more, err := vf.FindEntitiesByTagValue(ctx, oam.AssetType(assetType), name, value, contains, time.Time{}, limit)
	if err != nil {
		return nil, false, err
	}

	return convertAll(ents, more)
}

// FindByAttribute implements ai.ValueSearcher.
func (a Adapter) FindByAttribute(ctx context.Context, assetType, key, value string, limit int) ([]ai.Asset, bool, error) {
	vf, ok := a.Repo.(valueFinder)
	if !ok {
		return nil, false, ai.ErrValueSearchUnsupported
	}

	ents, more, err := vf.FindEntitiesByAttribute(ctx, oam.AssetType(assetType), key, value, time.Time{}, limit)
	if err != nil {
		return nil, false, err
	}

	return convertAll(ents, more)
}

func convertAll(ents []*dbt.Entity, more bool) ([]ai.Asset, bool, error) {
	out := make([]ai.Asset, 0, len(ents))
	for _, e := range ents {
		a, err := convert(e)
		if err != nil {
			return nil, false, err
		}

		out = append(out, a)
	}

	return out, more, nil
}
