// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

// nameKeeper keeps names on the survivors it holds; the others are gone.
type nameKeeper struct {
	stored map[string]bool
	asked  []string
}

func (k *nameKeeper) KeepMergedNames(_ context.Context, survivorID string, _ json.RawMessage,
	_ int) (MergeRecord, error) {
	k.asked = append(k.asked, survivorID)
	if !k.stored[survivorID] {
		return MergeRecord{}, ErrRecordGone
	}
	return MergeRecord{SurvivorTagIDs: []string{"tag-" + survivorID}}, nil
}

// Earlier merges get their names once: a merge whose record is gone is
// skipped and recorded, and a second pass asks about neither again. The
// names kept join the merge's record, so undoing it removes them.
func TestKeepMergedNamesOnce(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	mergeApplied(t, j, "dup-kept", "112", "142")
	mergeApplied(t, j, "dup-gone", "323", "324")

	k := &nameKeeper{stored: map[string]bool{"112": true}}
	kept, gone, err := j.KeepMergedNames(context.Background(), k)
	if err != nil || kept != 1 || gone != 1 {
		t.Fatalf("kept %d, gone %d, %v", kept, gone, err)
	}
	if kept, gone, err = j.KeepMergedNames(context.Background(), k); err != nil || kept+gone != 0 ||
		len(k.asked) != 2 {
		t.Errorf("a second pass kept %d, skipped %d, asked %v, %v", kept, gone, k.asked, err)
	}

	state, err := j.DuplicateState()
	if err != nil {
		t.Fatal(err)
	}
	if got := state["dup-kept"].Outcome.Merge.SurvivorTagIDs; len(got) != 1 || got[0] != "tag-112" {
		t.Errorf("the merge's record holds %v", got)
	}
}
