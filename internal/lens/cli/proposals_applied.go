// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/review"
)

// AppliedSummary counts, by kind, the graph changes the AI classifier applied
// automatically (a reviewer beginning "amass-ai"), so what the classifier did
// without a human in the loop can be surfaced. It is the applied-decision
// counterpart of PendingSummary.
type AppliedSummary struct {
	Ownership       int `json:"ownership"`
	Merges          int `json:"merges"`
	Identities      int `json:"identities"`
	NameKinds       int `json:"name_kinds"`
	ScopeExpansions int `json:"scope_expansions"`
	DocumentLeads   int `json:"document_leads"`
	Total           int `json:"total"`
}

// isAIReviewer reports whether a journal reviewer is the automatic classifier
// (the automatic attribution reviewer or a named model), not a human.
func isAIReviewer(reviewer string) bool {
	return strings.HasPrefix(reviewer, "amass-ai")
}

// AppliedByAISummary counts the decisions the AI applied to the graph on its
// own, by kind, whose latest outcome is applied by an automatic reviewer.
// When since is non-zero only decisions applied at or after it are counted,
// so a caller can report just the current run. It reads the same journal
// that "amass review" reads.
func AppliedByAISummary(j *review.Journal, since time.Time) (AppliedSummary, error) {
	var s AppliedSummary
	if j == nil {
		return s, errors.New("-journal required")
	}

	for _, k := range proposalKinds {
		if k.applied[0] == "" {
			continue
		}
		recs, err := k.read(j)
		if err != nil {
			return s, err
		}
		n := s.counter(k.key)
		for _, r := range recs.records() {
			if r.appliedByAI(since) {
				*n++
				s.Total++
			}
		}
	}
	return s, nil
}

// counter is the summary's count for a kind's key.
func (s *AppliedSummary) counter(key string) *int {
	switch key {
	case "ownership":
		return &s.Ownership
	case "merges":
		return &s.Merges
	case "identities":
		return &s.Identities
	case "name_kinds":
		return &s.NameKinds
	case "scope_expansions":
		return &s.ScopeExpansions
	case "document_leads":
		return &s.DocumentLeads
	}
	panic("no applied count for " + key)
}

// Line renders the applied summary as one sentence naming the counts by kind and
// pointing at the review command, or "" when the classifier applied nothing (so
// a caller prints it only when there is something to say).
func (s AppliedSummary) Line() string {
	if s.Total == 0 {
		return ""
	}

	var parts []string
	for _, k := range proposalKinds {
		if k.applied[0] == "" {
			continue
		}
		if part := kindSummary(*s.counter(k.key), k.applied); part != "" {
			parts = append(parts, part)
		}
	}
	return fmt.Sprintf("%d change(s) the AI made automatically: %s — review with 'amass review applied'",
		s.Total, strings.Join(parts, ", "))
}

// listApplied reports the changes the AI classifier applied to the graph
// (amass review applied), the applied-decision counterpart of the pending
// proposals listing. A detailed per-item view with evidence is surfaced through
// the MCP list and the end-of-run summary; this prints the by-kind counts.
func listApplied(j *review.Journal, format string, out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}

	s, err := AppliedByAISummary(j, time.Time{})
	if err != nil {
		return err
	}
	if format == "json" {
		return writeJSON(out, s)
	}

	line := s.Line()
	if line == "" {
		line = "the AI classifier has applied no changes"
	}
	_, err = fmt.Fprintln(out, line)
	return err
}

// AppliedProposalsText lists, for the MCP list, each change the AI classifier
// applied to the graph on its own, with the same detail "amass review" shows —
// the applied counterpart of PendingProposalsText. (enumeration_status gives
// the counts; this gives the items.)
func AppliedProposalsText(j *review.Journal) (string, error) {
	return AppliedProposalsTextLive(j, nil)
}

// AppliedProposalsTextLive is AppliedProposalsText, leaving out the changes
// whose entities exists says are gone.
func AppliedProposalsTextLive(j *review.Journal, exists EntityExists) (string, error) {
	items, err := DecisionItems(j)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	n := 0
	for _, d := range items {
		if d.Status != DecisionApplied || !live(exists, d.EntityIDs...) {
			continue
		}

		n++
		fmt.Fprintf(&b, "\n%s %s (applied by %s)\n%s\n", d.Kind, d.ID, d.Reviewer, d.Summary)
	}
	if n == 0 {
		return "The AI classifier has applied no changes.", nil
	}

	return fmt.Sprintf("%d change(s) the AI classifier applied automatically:\n", n) + b.String(), nil
}
