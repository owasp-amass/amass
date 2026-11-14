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

// gapLens answers an ownership-gap lens query from root.
func (a Agent) gapLens(ctx context.Context, root graph.Asset, out Investigation) (Investigation, error) {
	started := time.Now()
	report, err := lens.SearchOwnershipGaps(ctx, a.Runner.Graph, a.Runner.Catalog, root)
	out.recordTrace(started, InvestigationTraceEvent{Stage: "ownership_gap_lens", OutputPaths: len(report.Candidates),
		GraphNodes: report.Footprint, Incomplete: err != nil || report.Truncated, Detail: report.Reason})
	if err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.GapReport = &report
	out.Incomplete = report.Truncated
	out.Answer = lens.GapAnswer(report)
	return out, nil
}
