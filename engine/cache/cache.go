// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type Cache interface {
	GetAsset(a oam.Asset) (*types.Asset, bool)
	GetAssetsByType(t oam.AssetType) ([]*types.Asset, bool)
	SetAsset(a *types.Asset)
	GetRelations(r *types.Relation) ([]*types.Relation, bool)
	GetRelationsByType(rtype string) ([]*types.Relation, bool)
	GetIncomingRelations(asset *types.Asset, relationTypes ...string) ([]*types.Relation, bool)
	GetOutgoingRelations(asset *types.Asset, relationTypes ...string) ([]*types.Relation, bool)
	SetRelation(r *types.Relation)
	Close()
}
