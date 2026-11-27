// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lookalike

import (
	"slices"
	"testing"
)

func TestCandidates(t *testing.T) {
	r, err := LoadRules()
	if err != nil {
		t.Fatal(err)
	}

	c := r.Candidates("example.edu")
	for _, want := range []string{
		"exmple.edu",   // deletion
		"exapmle.edu",  // transposition
		"exsmple.edu",  // a for its neighbor s
		"exaample.edu", // a typed twice
		"exampkle.edu", // k typed next to l
		"example.com",  // another suffix
	} {
		if !slices.Contains(c, want) {
			t.Errorf("candidates lack %s", want)
		}
	}
	for _, unwanted := range []string{"example.edu", "exzzple.edu", "-xample.edu"} {
		if slices.Contains(c, unwanted) {
			t.Errorf("candidates include %s", unwanted)
		}
	}
	if len(c) > r.MaxCandidates || !slices.IsSorted(c) {
		t.Errorf("%d candidates, sorted %v", len(c), slices.IsSorted(c))
	}

	if c := r.Candidates("zzq.edu"); len(c) != 0 {
		t.Errorf("a short label has candidates: %v", c)
	}
	if c := r.Candidates("www.example.edu"); len(c) != 0 {
		t.Errorf("a name below a registered domain has candidates: %v", c)
	}
	if c := r.Candidates("example.co.uk"); !slices.Contains(c, "exmple.co.uk") || !slices.Contains(c, "example.com") {
		t.Errorf("a two-label suffix: %v", c)
	}
}
