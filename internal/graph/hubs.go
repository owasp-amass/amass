// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import "context"

// HubRule is the most holders a shared value may have before it is too
// common to be evidence about any one of them (internal/hubs), and whether
// the database derived it rather than the caller's fixed limit applying.
type HubRule struct {
	Limit   int
	Derived bool
}

// HubSource names a kind of shared value (internal/hubs Source): with Label
// set, the values a relation label links to their holders, which point at
// them ("in") or are listed by them ("out"), only the values of AssetType
// whose attribute Property equals Value when Value is set; otherwise, with
// AssetType and Property set, the exact values of that tag on assets of the
// type, only those starting with one of Prefixes when there are any, or of
// that stored attribute when Attribute is set.
type HubSource struct {
	Label     string
	Direction string
	AssetType string
	Property  string
	Value     string
	Prefixes  []string
	Attribute bool
}

// HubLimiter gives the hub rule for a kind of shared value.
type HubLimiter interface {
	HubRule(ctx context.Context, src HubSource, fallback int) HubRule
}

// SourceHubRule returns g's hub rule for the values of src, or fallback, not
// derived, when g cannot say.
func SourceHubRule(ctx context.Context, g Graph, src HubSource, fallback int) HubRule {
	if h, ok := g.(HubLimiter); ok {
		return h.HubRule(ctx, src, fallback)
	}
	return HubRule{Limit: fallback}
}

// HubRuleFor returns g's hub rule for values linked by label in direction.
func HubRuleFor(ctx context.Context, g Graph, label, direction string, fallback int) HubRule {
	return SourceHubRule(ctx, g, HubSource{Label: label, Direction: direction}, fallback)
}

// HubLimit returns the limit of g's hub rule for values linked by label in
// direction.
func HubLimit(ctx context.Context, g Graph, label, direction string, fallback int) int {
	return HubRuleFor(ctx, g, label, direction, fallback).Limit
}
