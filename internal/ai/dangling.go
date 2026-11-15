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

// danglingLens answers a dangling DNS lens query.
func (a Agent) danglingLens(ctx context.Context, root graph.Asset, out Investigation) (Investigation, error) {
	started := time.Now()
	report, err := lens.FindDanglingDNS(ctx, a.Runner.Graph, a.Runner.Catalog, root, a.Runner.LensLimits)
	out.recordTrace(started, InvestigationTraceEvent{Stage: "dangling_lens", OutputPaths: len(report.Findings),
		GraphNodes: report.Footprint, Incomplete: err != nil || report.Truncated, Detail: report.Reason})
	if err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.DanglingReport = &report
	out.Incomplete = report.Truncated
	out.Answer = strings.TrimRight(lens.FormatDanglingReport(report), "\n")
	return out, nil
}
