// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
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

	// A trained ownership model ranks and decides the candidates the same way
	// automatic attribution does; without one, the rules' decision stands.
	if err := review.ScoreGapCandidates(&report, a.Runner.Attribution); err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.GapReport = &report
	out.Incomplete = report.Truncated
	out.Answer = lens.GapAnswer(report)
	out.Diagram = GapDiagram(report)
	return out, nil
}
