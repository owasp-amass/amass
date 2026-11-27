// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"github.com/owasp-amass/amass/v5/internal/collect"
	"github.com/owasp-amass/amass/v5/internal/graph"
)

// CollectionPlan is a proposal, never permission; see collect.Plan. A model
// must not be able to launch discovery by calling a read-only graph tool:
// only the collect command and the MCP operator tools, behind their own
// approvals, start collection.
type CollectionPlan = collect.Plan

// PlanCollection computes the passive collection plan for target. It does
// not touch the Internet or the Asset Database.
func PlanCollection(target graph.AssetSelector) CollectionPlan {
	return collect.NewPlan(target, collect.Passive)
}
