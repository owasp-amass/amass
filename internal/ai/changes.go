// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// changesLens answers a changes lens query over the default window.
func (a Agent) changesLens(ctx context.Context, root graph.Asset, out Investigation) (Investigation, error) {
	started := time.Now()
	report, err := lens.FindChanges(ctx, a.Runner.Graph, a.Runner.Catalog, root, time.Time{}, a.Runner.LensLimits)
	out.recordTrace(started,
		InvestigationTraceEvent{Stage: "changes_lens", OutputPaths: len(report.NewAssets) + len(report.QuietAssets),
			GraphNodes: report.Footprint, Incomplete: err != nil || report.Truncated, Detail: report.Reason})
	if err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.ChangesReport = &report
	out.Incomplete = report.Truncated
	out.Answer = strings.TrimRight(lens.FormatChangesReport(report), "\n")
	return out, nil
}
