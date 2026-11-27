// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
)

type AssetSearchCatalog interface {
	SearchFields() []AssetSearchSchema
}

type AssetResolver interface {
	ResolveAsset(context.Context, AssetSelector, int) (AssetResolution, error)
}
