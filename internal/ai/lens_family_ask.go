// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"time"
)

// LensFamily asks for the organization family of an enumerated domain: the
// organizations that are its institution or affiliates, the networks that
// serve it and the other domains they serve. The answer is built in Go from
// FindOrganizationFamily and never reaches the model.
const LensFamily = "family"

// familyLens answers a family lens query from a domain.
func (a Agent) familyLens(ctx context.Context, root Asset, out Investigation) (Investigation, error) {
	started := time.Now()
	report, err := FindOrganizationFamily(ctx, a.Runner.Graph, root)
	out.recordTrace(started, InvestigationTraceEvent{Stage: "family_lens", OutputPaths: len(report.Members),
		Incomplete: err != nil || report.Truncated, Detail: report.Reason})
	if err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.FamilyReport = &report
	out.Incomplete = report.Truncated
	out.Answer = strings.TrimRight(FormatFamilyReport(report), "\n")
	return out, nil
}
