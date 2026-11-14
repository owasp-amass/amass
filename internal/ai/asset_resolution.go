// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"

	"github.com/owasp-amass/amass/v5/internal/ai/graph"
)

type AssetSearchCatalog interface {
	SearchFields() []graph.AssetSearchSchema
}

type AssetResolver interface {
	ResolveAsset(context.Context, graph.AssetSelector, int) (graph.AssetResolution, error)
}
