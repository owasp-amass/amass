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

// groupVendorsLens answers a group_vendors lens query.
func (a Agent) groupVendorsLens(ctx context.Context, root graph.Asset, out Investigation) (Investigation, error) {
	started := time.Now()
	report, err := lens.FindGroupVendors(ctx, a.Runner.Graph, a.Runner.Catalog, root, lens.LensLimits{})
	out.recordTrace(started, InvestigationTraceEvent{Stage: "group_vendors_lens", OutputPaths: len(report.Vendors),
		Incomplete: err != nil || report.Truncated, Detail: report.Reason})
	if err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.GroupVendorReport = &report
	out.Incomplete = report.Truncated
	out.Answer = strings.TrimRight(lens.FormatGroupVendorReport(report), "\n")
	return out, nil
}
