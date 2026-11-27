// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/review"
)

// PendingSummary counts the proposals in a journal that are still awaiting a
// decision, grouped by kind. It lets a finished enumeration, or any client
// polling a run, tell the user how many proposals are waiting and of what kind
// without their having to run `amass review proposals` — closing the gap where
// proposals surfaced only to someone who knew to look.
type PendingSummary struct {
	Ownership   int `json:"ownership"`
	Merges      int `json:"merges"`
	Identities  int `json:"identities"`
	PersonNamed int `json:"person_named"`
	OrgNamed    int `json:"org_named"`
	Relations   int `json:"relations"`
	NameKinds   int `json:"name_kinds"`
	Expansions  int `json:"scope_expansions"`
	Total       int `json:"total"`
}

// PendingProposalsSummary counts, by kind, the journal's proposals that are
// still awaiting a decision. It reads the same journal `amass review` reads, so
// its counts match what a review session would show.
func PendingProposalsSummary(j *review.Journal) (PendingSummary, error) {
	return PendingProposalsSince(j, time.Time{})
}

// PendingProposalsSince counts, by kind, the proposals still awaiting a
// decision that were recorded at or after since, so a run reports the
// proposals it raised rather than the whole journal's backlog. A zero since
// counts them all. A proposal recorded without a time is counted only then.
func PendingProposalsSince(j *review.Journal, since time.Time) (PendingSummary, error) {
	var s PendingSummary
	if j == nil {
		return s, errors.New("-journal required")
	}

	kinds, recs, err := listedKinds(j)
	if err != nil {
		return s, err
	}
	for i, k := range kinds {
		if k.pending[0] == "" {
			continue // never pending, such as a contribution
		}
		n := s.counter(k.key)
		for _, r := range recs[i].records() {
			if r.isPending() && (since.IsZero() || !r.created.Before(since)) {
				*n++
				s.Total++
			}
		}
	}
	return s, nil
}

// counter is the summary's count for a kind's key.
func (s *PendingSummary) counter(key string) *int {
	switch key {
	case "ownership":
		return &s.Ownership
	case "merges":
		return &s.Merges
	case "identities":
		return &s.Identities
	case "person_named":
		return &s.PersonNamed
	case "org_named":
		return &s.OrgNamed
	case "relations":
		return &s.Relations
	case "name_kinds":
		return &s.NameKinds
	case "scope_expansions":
		return &s.Expansions
	}
	panic("no pending count for " + key)
}

// Line renders the summary as a single sentence that names the counts by kind
// and points at the review command, or "" when nothing is pending (so a caller
// can print it only when there is something to say).
func (s PendingSummary) Line() string {
	if s.Total == 0 {
		return ""
	}

	var parts []string
	for _, k := range proposalKinds {
		if k.heading == "" || k.pending[0] == "" {
			continue
		}
		if part := kindSummary(*s.counter(k.key), k.pending); part != "" {
			parts = append(parts, part)
		}
	}
	return fmt.Sprintf("%d proposal(s) awaiting review: %s — review with 'amass review proposals'",
		s.Total, strings.Join(parts, ", "))
}
