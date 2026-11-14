// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	if err := RunLens(nil, &out, &errout, nil); err == nil {
		t.Error("amass lens ran without a name")
	} else {
		for name := range lensOps {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("lens usage lacks %s: %v", name, err)
			}
		}
	}
	if err := RunLens(nil, &out, &errout, []string{"ask"}); err == nil {
		t.Error("amass lens ran an AI operation")
	}
	if err := RunReview(nil, &out, &errout, []string{"family"}); err == nil {
		t.Error("amass review ran a lens")
	}
}

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Time{
		"":                     {},
		"2026-11-01":           time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		"2026-11-01T08:00:00Z": time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC),
		"7d":                   now.AddDate(0, 0, -7),
		"72h":                  now.Add(-72 * time.Hour),
	} {
		got, err := parseSince(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("parseSince(%q) = %s, %v; want %s", in, got, err, want)
		}
	}
	if _, err := parseSince("last week", now); err == nil {
		t.Error("an unreadable -since was accepted")
	}
}
