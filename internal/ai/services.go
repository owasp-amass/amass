// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai/graph"
	"github.com/owasp-amass/amass/v5/internal/ai/lens"
)

// servicesLens answers a services lens query.
func (a Agent) servicesLens(ctx context.Context, root graph.Asset, out Investigation) (Investigation, error) {
	started := time.Now()
	report, err := lens.FindServices(ctx, a.Runner.Graph, a.Runner.Catalog, root, lens.LensLimits{})
	out.recordTrace(started, InvestigationTraceEvent{Stage: "services_lens", OutputPaths: len(report.Services),
		GraphNodes: report.Footprint, Incomplete: err != nil || report.Truncated, Detail: report.Reason})
	if err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.ServicesReport = &report
	out.Incomplete = report.Truncated
	out.Answer = strings.TrimRight(lens.FormatServicesReport(report), "\n")
	return out, nil
}
