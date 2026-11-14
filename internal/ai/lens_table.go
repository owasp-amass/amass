// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// tableLens answers a table lens query from root.
func (a Agent) tableLens(ctx context.Context, root graph.Asset, q Query, opts AdaptiveOptions, out Investigation) (Investigation, error) {
	started := time.Now()
	report, err := lens.SearchTable(ctx, a.Runner.Graph, a.Runner.Catalog, root, q.TargetTypes[0], q.Columns,
		inventoryLimit(opts))
	out.recordTrace(started, InvestigationTraceEvent{Stage: "table_lens", OutputPaths: len(report.Rows),
		Incomplete: err != nil || report.Truncated, Detail: report.Reason})
	if err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.TableReport = &report
	out.Incomplete = report.Truncated
	out.Answer = lens.TableAnswer(report)
	return out, nil
}
