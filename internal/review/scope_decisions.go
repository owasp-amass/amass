// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// DeclinedScopeExpansions returns the IDs of the expansions a person turned
// down (their latest record is a rejection or a retraction by a reviewer who
// is not amass-ai), so no later enumeration widens its scope to them again.
// One the reevaluation sweep retracted is not among them: the evidence may
// return.
func (j *Journal) DeclinedScopeExpansions() (map[string]bool, error) {
	all, err := j.ScopeExpansions()
	if err != nil {
		return nil, err
	}

	out := map[string]bool{}
	for _, e := range all {
		if (e.Status == ProposalRetracted || e.Status == ProposalRejected) && !isAIReviewer(e.Reviewer) {
			out[e.ID] = true
		}
	}
	return out, nil
}

// ApprovedScopeExpansions returns the expansions whose latest record is a
// person's approval, by ID, so a later enumeration that finds the candidate
// again admits it on that approval.
func (j *Journal) ApprovedScopeExpansions() (map[string]ScopeExpansion, error) {
	all, err := j.ScopeExpansions()
	if err != nil {
		return nil, err
	}

	out := map[string]ScopeExpansion{}
	for _, e := range all {
		if e.Status == ProposalApplied && e.Reviewer != "" && !isAIReviewer(e.Reviewer) {
			out[e.ID] = e
		}
	}
	return out, nil
}

// PendingScopeExpansions returns the expansions waiting for a person.
func (j *Journal) PendingScopeExpansions() ([]ScopeExpansion, error) {
	all, err := j.ScopeExpansions()
	if err != nil {
		return nil, err
	}

	var out []ScopeExpansion
	for _, e := range all {
		if e.Status == ProposalPending {
			out = append(out, e)
		}
	}
	return out, nil
}

// DecideScopeExpansion records a person's decision on a pending expansion:
// ProposalApplied approves it (the next enumeration that finds the candidate
// admits it), ProposalRejected turns it down for good.
func DecideScopeExpansion(j *Journal, id, status, reviewer string) (ScopeExpansion, error) {
	if status != ProposalApplied && status != ProposalRejected {
		return ScopeExpansion{}, fmt.Errorf("a scope expansion is approved or rejected, not %q", status)
	}
	if reviewer == "" || isAIReviewer(reviewer) {
		return ScopeExpansion{}, errors.New("a person's name is required as the reviewer")
	}

	all, err := j.ScopeExpansions()
	if err != nil {
		return ScopeExpansion{}, err
	}
	for _, e := range all {
		if e.ID != id {
			continue
		}
		if e.Status != ProposalPending {
			return ScopeExpansion{}, fmt.Errorf("scope expansion %s is %s, not pending", id, e.Status)
		}

		// a zero time is filled with now when recorded
		e.Status, e.Reviewer, e.At = status, reviewer, time.Time{}
		if err := j.RecordScopeExpansion(e); err != nil {
			return ScopeExpansion{}, err
		}
		return e, nil
	}
	return ScopeExpansion{}, fmt.Errorf("no scope expansion %s in the journal", id)
}

// FormatScopeExpansions renders scope expansions for review.
func FormatScopeExpansions(entries []ScopeExpansion) string {
	if len(entries) == 0 {
		return "No scope expansions in the journal.\n"
	}

	var b strings.Builder
	for i, e := range entries {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s  %s\n", e.ID, strings.ToUpper(e.Status))
		fmt.Fprintf(&b, "  widen %s's scope to %s %s (confidence %d)\n", e.Org, e.Kind(), e.Asset, e.Confidence)
		if len(e.Signals) > 0 {
			fmt.Fprintf(&b, "  evidence: %s\n", strings.Join(e.Signals, "; "))
		}
		if a := e.Advice; a != nil && e.Status == ProposalPending {
			fmt.Fprintf(&b, "  advice: %s would %s (confidence %d)", a.Model, a.Decision, a.Confidence)
			if a.Reason != "" {
				fmt.Fprintf(&b, ": %s", a.Reason)
			}
			b.WriteString("\n")
		}
		if e.Reviewer != "" {
			fmt.Fprintf(&b, "  by %s\n", e.Reviewer)
		}
	}
	return b.String()
}
