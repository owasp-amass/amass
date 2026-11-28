// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/hubs"
)

// HubRule implements graph.HubLimiter with the database's thresholds, or
// with fallback when the adapter keeps hub limits fixed.
func (a Adapter) HubRule(ctx context.Context, src graph.HubSource, fallback int) graph.HubRule {
	if a.FixedHubs {
		return graph.HubRule{Limit: fallback}
	}
	n, derived := hubs.For(a.Repo).Threshold(ctx, hubs.Source(src)).For(fallback)
	return graph.HubRule{Limit: n, Derived: derived}
}
