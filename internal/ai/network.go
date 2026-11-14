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

// networkLens answers a network lens query.
func (a Agent) networkLens(ctx context.Context, root graph.Asset, out Investigation) (Investigation, error) {
	started := time.Now()
	report, err := lens.FindNetworkInfrastructure(ctx, a.Runner.Graph, a.Runner.Catalog, root, lens.LensLimits{})
	out.recordTrace(started, InvestigationTraceEvent{Stage: "network_lens", OutputPaths: len(report.Networks),
		GraphNodes: report.Footprint, Incomplete: err != nil || report.Truncated, Detail: report.Reason})
	if err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.NetworkReport = &report
	out.Incomplete = report.Truncated
	out.Answer = strings.TrimRight(lens.FormatNetworkReport(report), "\n")
	return out, nil
}
