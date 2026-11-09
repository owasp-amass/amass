// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import "time"

// InvestigationTraceEvent describes one completed, synchronous stage of an
// investigation. It is not a prediction or model-authored execution log.
// Counts are actual bounded operations reported by the executor.
type InvestigationTraceEvent struct {
	Stage               string `json:"stage"`
	DurationMS          int64  `json:"duration_ms"`
	InputPaths          int    `json:"input_paths,omitempty"`
	OutputPaths         int    `json:"output_paths,omitempty"`
	GraphNodes          int    `json:"graph_nodes,omitempty"`
	GraphEdges          int    `json:"graph_edges,omitempty"`
	PathExpansions      int    `json:"path_expansions,omitempty"`
	EdgeEvidenceLookups int    `json:"edge_evidence_lookups,omitempty"`
	EvidenceRecords     int    `json:"evidence_records,omitempty"`
	Incomplete          bool   `json:"incomplete"`
	Detail              string `json:"detail,omitempty"`
}

func traceElapsed(start time.Time) int64 {
	v := time.Since(start).Milliseconds()
	if v < 0 {
		return 0
	}

	return v
}

func (i *Investigation) recordTrace(start time.Time, event InvestigationTraceEvent) {
	event.DurationMS = traceElapsed(start)
	i.Trace = append(i.Trace, event)
}
