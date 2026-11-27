// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"fmt"
	"sort"
	"strings"
)

// MinDecidedForPrecision is the number of reviewed proposals a signal needs
// before its precision says much; below it the report flags the signal.
const MinDecidedForPrecision = 5

// SignalPrecision is how reviewers have judged the ownership proposals one
// catalog signal stood behind.
type SignalPrecision struct {
	Signal    string  `json:"signal"`
	Applied   int     `json:"applied"`
	Rejected  int     `json:"rejected"`
	Retracted int     `json:"retracted"`
	Pending   int     `json:"pending"`
	Precision float64 `json:"precision"`
	// Thin is true when fewer than MinDecidedForPrecision proposals were
	// applied or rejected, so Precision is not yet a measure.
	Thin bool `json:"thin"`
}

// Decided is the number of proposals a reviewer applied or rejected.
func (s SignalPrecision) Decided() int { return s.Applied + s.Rejected }

// SignalPrecisions counts, for each signal named by an ownership proposal,
// the proposals applied, rejected, retracted and still pending. Precision is
// applied / (applied + rejected). A retraction is reported but not counted
// against the signal, since proposals are also retracted when a merge or a
// later run supersedes them. Signals are ordered by precision, lowest first,
// so the ones to tune come first; thin signals follow.
func SignalPrecisions(entries []OwnershipEntry) []SignalPrecision {
	by := map[string]*SignalPrecision{}
	for _, e := range entries {
		for _, id := range e.Proposal.SignalIDs {
			s, ok := by[id]
			if !ok {
				s = &SignalPrecision{Signal: id}
				by[id] = s
			}

			switch e.Status {
			case ProposalApplied:
				s.Applied++
			case ProposalRejected:
				s.Rejected++
			case ProposalRetracted:
				s.Retracted++
			case ProposalPending:
				s.Pending++
			}
		}
	}

	out := make([]SignalPrecision, 0, len(by))
	for _, s := range by {
		if d := s.Decided(); d > 0 {
			s.Precision = float64(s.Applied) / float64(d)
		}
		s.Thin = s.Decided() < MinDecidedForPrecision
		out = append(out, *s)
	}

	sort.Slice(out, func(a, b int) bool {
		if out[a].Thin != out[b].Thin {
			return !out[a].Thin
		}
		if out[a].Precision != out[b].Precision {
			return out[a].Precision < out[b].Precision
		}
		return out[a].Signal < out[b].Signal
	})
	return out
}

// FormatSignalPrecisions renders the report for amass review signal-precision.
func FormatSignalPrecisions(rows []SignalPrecision) string {
	if len(rows) == 0 {
		return "No ownership proposals in the journal name a signal."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%-34s %9s %7s %8s %9s %7s\n", "signal", "precision", "applied", "rejected", "retracted", "pending")
	for _, s := range rows {
		precision := fmt.Sprintf("%.2f", s.Precision)
		if s.Decided() == 0 {
			precision = "-"
		}
		if s.Thin {
			precision += "*"
		}

		fmt.Fprintf(&b, "%-34s %9s %7d %8d %9d %7d\n", s.Signal, precision, s.Applied, s.Rejected, s.Retracted, s.Pending)
	}
	fmt.Fprintf(&b, "* fewer than %d proposals applied or rejected", MinDecidedForPrecision)

	return b.String()
}
