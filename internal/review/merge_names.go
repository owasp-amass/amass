// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// ErrRecordGone is returned by a MergeNameKeeper when the record a merge
// went into is no longer stored, such as after the database was reset.
var ErrRecordGone = errors.New("the merged record is no longer stored")

// MergeNameKeeper keeps a merged duplicate's names on the record that holds
// it now: the more complete name shown, every other name kept.
type MergeNameKeeper interface {
	KeepMergedNames(ctx context.Context, survivorID string, duplicate json.RawMessage, confidence int) (MergeRecord,
		error)
}

// mergeNames records the names kept for a merge applied before merges kept
// every name. Its additions join the merge's record, so undoing the merge
// removes them.
type mergeNames struct {
	ProposalID string      `json:"proposal_id"`
	Merge      MergeRecord `json:"merge"`
	At         time.Time   `json:"at"`
}

// addNames folds kept names into an applied merge's record.
func (m *MergeRecord) addNames(add MergeRecord) {
	m.NameEdges = append(m.NameEdges, add.NameEdges...)
	m.SurvivorTagIDs = append(m.SurvivorTagIDs, add.SurvivorTagIDs...)
	if len(m.SurvivorBefore) == 0 {
		m.SurvivorBefore = add.SurvivorBefore
	}
}

// KeepMergedNames gives each applied merge made before merges kept every
// name the names it dropped: on the record holding the survivor now, the
// more complete name is shown and the others kept. It returns how many
// merges it gave their names, and how many it skipped because their merged
// record is no longer stored. Each is recorded, so neither is tried again.
func (j *Journal) KeepMergedNames(ctx context.Context, k MergeNameKeeper) (kept, gone int, err error) {
	lines, err := j.History()
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, nil
	} else if err != nil {
		return 0, 0, err
	}
	done := map[string]bool{}
	for _, line := range lines {
		var rec struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(line, &rec) == nil && rec.Kind == "duplicate_names" {
			var m mergeNames
			if json.Unmarshal(rec.Data, &m) == nil {
				done[m.ProposalID] = true
			}
		}
	}

	state, err := j.DuplicateState()
	if err != nil {
		return 0, 0, err
	}
	r := readRedirects(lines)
	var errs []error
	for id, e := range state {
		if err := ctx.Err(); err != nil {
			return kept, gone, err
		}
		m := e.Outcome
		if e.Status != ProposalApplied || m == nil || m.Merge == nil || done[id] ||
			len(m.Merge.NameEdges) > 0 || len(m.Merge.SurvivorBefore) > 0 {
			continue
		}

		add, err := k.KeepMergedNames(ctx, r.Entity(m.Merge.SurvivorID), m.Merge.DuplicateAsset,
			MergeConfidence(e.Proposal))
		switch {
		case errors.Is(err, ErrRecordGone):
			gone++
		case err != nil:
			// the other merges go on
			errs = append(errs, fmt.Errorf("merge %s: %w", id, err))
			continue
		default:
			kept++
		}
		if err := j.append("duplicate_names", mergeNames{ProposalID: id, Merge: add,
			At: time.Now().UTC()}); err != nil {
			return kept, gone, err
		}
	}
	return kept, gone, errors.Join(errs...)
}
