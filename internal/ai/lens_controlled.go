// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai/graph"
	"github.com/owasp-amass/amass/v5/internal/ai/lens"
)

// controlledLens answers a controlled lens query from root.
func (a Agent) controlledLens(ctx context.Context, root graph.Asset, targets []string, opts AdaptiveOptions, out Investigation) (Investigation, error) {
	started := time.Now()
	report, err := lens.SearchControlled(ctx, a.Runner.Graph, a.Runner.Catalog, root, targets, inventoryLimit(opts))
	out.recordTrace(started, InvestigationTraceEvent{Stage: "controlled_lens", OutputPaths: len(report.Matches),
		GraphNodes: report.Footprint, Incomplete: err != nil || report.Truncated, Detail: report.Reason})
	if err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.ControlledReport = &report
	out.Matches = report.Matches
	out.Incomplete = report.Truncated
	out.Answer = lens.ControlledAnswer(report)
	if len(report.Matches) > 0 && len(report.Matches) <= maxInventoryDiagramPaths {
		out.Diagram = adaptiveDiagram(report.Matches)
	}

	return out, nil
}
