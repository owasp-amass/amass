// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"testing"
)

func TestJournal(t *testing.T) {
	j := &Journal{Path: t.TempDir() + "/proposals.jsonl"}
	if err := j.Submit(Proposal{ID: "test", Status: "proposed"}); err != nil {
		t.Fatal(err)
	}
	if err := j.Review("test", "accepted", "analyst"); err != nil {
		t.Fatal(err)
	}

	rows, err := j.History()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows=%d", len(rows))
	}
}
