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

// reportLens answers a query with a registered subject lens.
func (a Agent) reportLens(ctx context.Context, l lens.SubjectLens, root graph.Asset, out Investigation) (Investigation, error) {
	started := time.Now()
	r, err := l.Find(ctx, a.Runner.Graph, a.Runner.Catalog, root, lens.Options{})
	partial, reason := false, ""
	if r != nil {
		partial, reason = r.Partial()
	}
	out.recordTrace(started, InvestigationTraceEvent{Stage: l.Name + "_lens", Incomplete: err != nil || partial,
		Detail: reason})
	if err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.LensReport = r
	out.Incomplete = partial
	out.Answer = strings.TrimRight(r.Text(), "\n")
	return out, nil
}
