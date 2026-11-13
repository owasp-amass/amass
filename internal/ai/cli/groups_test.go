// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLensAndReviewCommands(t *testing.T) {
	var out, errout bytes.Buffer
	if err := RunReview(nil, &out, &errout, []string{"signals"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Why it counts") || errout.Len() != 0 {
		t.Errorf("review signals: out %q, errout %q", out.String()[:min(80, out.Len())], errout.String())
	}

	// Flags come after the name.
	out.Reset()
	journal := filepath.Join(t.TempDir(), "review.jsonl")
	if err := RunReview(nil, &out, &errout, []string{"proposals", "-journal", journal}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No ownership proposals") {
		t.Errorf("review proposals: %q", out.String())
	}

	// Flags may also come first, as compose passes -config.
	out.Reset()
	if err := RunReview(nil, &out, &errout, []string{"-journal", journal, "-format", "text", "proposals"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No ownership proposals") {
		t.Errorf("flags first: %q", out.String())
	}

	if err := RunLens(nil, &out, &errout, nil); err == nil || !strings.Contains(err.Error(), "family|identity") {
		t.Errorf("lens without a name: %v", err)
	}
	if err := RunLens(nil, &out, &errout, []string{"ask"}); err == nil {
		t.Error("amass lens ran an AI operation")
	}
	if err := RunReview(nil, &out, &errout, []string{"family"}); err == nil {
		t.Error("amass review ran a lens")
	}

	// amass ai takes the operation first or last.
	out.Reset()
	if err := Run(nil, &out, &errout, []string{"signals", "-format", "text"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Why it counts") {
		t.Errorf("operation first: %q", out.String()[:min(80, out.Len())])
	}

	// The old amass ai form still works, with a note.
	out.Reset()
	errout.Reset()
	if err := Run(nil, &out, &errout, []string{"-format", "text", "duplicate-signals"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errout.String(), "amass ai duplicate-signals is now amass review duplicate-signals") {
		t.Errorf("deprecation note: %q", errout.String())
	}
}

// Every amass lens and amass review name must run a known operation; a name
// missing from operations fails only when it is used.
func TestGroupNamesRunKnownOperations(t *testing.T) {
	for group, ops := range map[string]map[string]string{"lens": lensOps, "review": reviewOps} {
		for name, op := range ops {
			if !slices.Contains(operations, op) {
				t.Errorf("amass %s %s runs %q, which is not a known operation", group, name, op)
			}
		}
	}
}
