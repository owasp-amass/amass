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

// orgGroupLens answers an org_group lens query.
func (a Agent) orgGroupLens(ctx context.Context, root graph.Asset, out Investigation) (Investigation, error) {
	started := time.Now()
	report, err := lens.FindCorporateGroup(ctx, a.Runner.Graph, root)
	out.recordTrace(started, InvestigationTraceEvent{Stage: "org_group_lens", OutputPaths: len(report.Members),
		Incomplete: err != nil || report.Truncated, Detail: report.Reason})
	if err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.OrgGroupReport = &report
	out.Incomplete = report.Truncated
	out.Answer = strings.TrimRight(lens.FormatGroupReport(report), "\n")
	return out, nil
}
