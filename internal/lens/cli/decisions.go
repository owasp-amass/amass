// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/review"
)

// Decision item statuses: a proposal awaiting the user's decision, or a change
// the AI classifier already applied on its own.
const (
	DecisionPending = "pending"
	DecisionApplied = "applied"
)

// DecisionItem is one thing a watcher should tell the user about: a proposal
// that now awaits a decision, or a change the AI classifier applied to the
// graph without a human (an "amass-ai" reviewer). Summary is the same text
// "amass review" shows for it.
type DecisionItem struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Status   string `json:"status"`
	Reviewer string `json:"reviewer,omitempty"`
	Summary  string `json:"summary"`
	// EntityIDs are the stored assets the item is about, so a listing can
	// leave out items left over from a database that was since wiped.
	EntityIDs []string `json:"entity_ids,omitempty"`
}

// Live reports whether every entity the item is about is still stored.
func (d DecisionItem) Live(exists EntityExists) bool { return live(exists, d.EntityIDs...) }

func (d DecisionItem) key() string { return d.Kind + "\x00" + d.ID + "\x00" + d.Status }

// DecisionChanges are the decision items that appeared in the journal after a
// cursor, and the cursor to pass next time.
type DecisionChanges struct {
	Items []DecisionItem `json:"items"`
	// Cursor marks how far the journal has been read: the number of its
	// records. An empty cursor in a request means "from now on".
	Cursor string `json:"cursor"`
	// Reset is true when the journal shrank below the cursor (a file journal
	// reset alongside a database wipe), so every current item is reported
	// again.
	Reset bool `json:"reset,omitempty"`
}

// DecisionsSince reports the pending proposals and AI-applied changes that
// appeared in the journal after cursor. It rebuilds the decision state as of
// the cursor and as of the journal's last record, with the same readers
// "amass review" uses, and returns the items present now that were not then —
// so it needs no timestamps and keeps no state between calls. An empty cursor
// returns no items and the cursor for the journal's current end. A journal
// kept in the database reads only the records appended since its last read.
func DecisionsSince(j *review.Journal, cursor string) (DecisionChanges, error) {
	var out DecisionChanges
	if j == nil {
		return out, errors.New("no review journal is configured")
	}

	var start int
	if cursor != "" {
		n, err := strconv.Atoi(cursor)
		if err != nil || n < 0 {
			return out, fmt.Errorf("invalid cursor %q", cursor)
		}
		start = n
	}

	lines, err := j.History()
	if errors.Is(err, os.ErrNotExist) {
		lines, err = nil, nil
	}
	if err != nil {
		return out, err
	}
	end := len(lines)
	out.Cursor = strconv.Itoa(end)
	if cursor == "" {
		return out, nil
	}
	if start > end {
		out.Reset, start = true, 0
	}
	if start == end {
		return out, nil
	}

	before, err := DecisionItems(review.JournalOf(lines[:start]))
	if err != nil {
		return out, err
	}
	now, err := DecisionItems(review.JournalOf(lines))
	if err != nil {
		return out, err
	}

	seen := make(map[string]bool, len(before))
	for _, d := range before {
		seen[d.key()] = true
	}
	for _, d := range now {
		if !seen[d.key()] {
			out.Items = append(out.Items, d)
		}
	}

	return out, nil
}

// DecisionItems lists the journal's proposals awaiting a decision and the
// changes the AI applied automatically, by kind: the same proposals
// PendingProposalsSummary counts and the same changes AppliedByAISummary
// counts.
func DecisionItems(j *review.Journal) ([]DecisionItem, error) {
	var out []DecisionItem
	for _, k := range proposalKinds {
		recs, err := k.read(j)
		if err != nil {
			return nil, err
		}
		recs.each(func(r record, text string) {
			item := DecisionItem{Kind: k.name, ID: r.id, Summary: strings.TrimSpace(text), EntityIDs: r.entities}
			switch {
			case k.heading != "" && r.isPending():
				item.Status = DecisionPending
			case k.applied[0] != "" && r.appliedByAI(time.Time{}):
				item.Status, item.Reviewer = DecisionApplied, r.reviewer
			default:
				return
			}
			out = append(out, item)
		})
	}
	return out, nil
}
