// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package brute

import (
	"slices"
	"sort"
	"strings"
	"testing"
)

func sorted(s []string) string {
	s = slices.Clone(s)
	sort.Strings(s)
	return strings.Join(s, " ")
}

func TestDeletions(t *testing.T) {
	if got, want := sorted(deletions([]string{"abc"})), "ab ac bc"; got != want {
		t.Errorf("deletions(abc) = %q, want %q", got, want)
	}
	if got := deletions([]string{"a"}); len(got) != 0 {
		t.Errorf("deleting the only character left %q", got)
	}
}

func TestSubstitutions(t *testing.T) {
	if got, want := sorted(substitutions([]string{"abc"}, "xy")), "axc ayc abx aby xbc ybc"; got != sorted(
		strings.Fields(want)) {
		t.Errorf("substitutions(abc) = %q, want %q", got, sorted(strings.Fields(want)))
	}
}

func TestAdditions(t *testing.T) {
	// Labels of several lengths, since a rune slice may have spare capacity.
	for _, label := range []string{"ab", "abc", "abcde", "abcdefg"} {
		got := additions([]string{label}, "x")
		var want []string
		for i := 0; i <= len(label); i++ {
			want = append(want, label[:i]+"x"+label[i:])
		}
		if sorted(got) != sorted(want) {
			t.Errorf("additions(%s) = %q, want %q", label, sorted(got), sorted(want))
		}
	}
}

func TestFuzzyLabelSearches(t *testing.T) {
	got := fuzzyLabelSearches("ab.example.com", 1, "x-")
	want := []string{"ab", "xab", "axb", "abx", "a-b", "b", "a", "xb", "ax", "a-"}
	set := map[string]bool{}
	for _, g := range got {
		if !strings.HasSuffix(g, ".example.com") {
			t.Fatalf("guess %q left the domain", g)
		}

		set[strings.TrimSuffix(g, ".example.com")] = true
	}
	for _, w := range want {
		label := strings.Trim(w, "-")
		if !set[label] {
			t.Errorf("fuzzy guesses lack %q: %q", label, sorted(got))
		}
	}
	for label := range set {
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") || label == "" {
			t.Errorf("invalid label %q", label)
		}
	}
	if got := fuzzyLabelSearches("localhost", 1, "x"); len(got) != 0 {
		t.Errorf("a name without a domain gave %q", got)
	}
}

func TestFlipNumbers(t *testing.T) {
	got := flipNumbers("web1.example.com")
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, want := range []string{"web0.example.com", "web9.example.com", "web.example.com"} {
		if !set[want] {
			t.Errorf("flipNumbers(web1) lacks %s: %q", want, sorted(got))
		}
	}
	if got := flipNumbers("www.example.com"); len(got) != 0 {
		t.Errorf("a label without digits gave %q", got)
	}
	// The digits of the domain are not flipped.
	for _, g := range flipNumbers("db2.ex4mple.com") {
		if !strings.HasSuffix(g, ".ex4mple.com") {
			t.Errorf("the domain was changed: %s", g)
		}
	}
}

func TestFlipWordsAndAffixes(t *testing.T) {
	if got, want := sorted(flipWords("dev-api.example.com", []string{"prod"})),
		"dev-prod.example.com prod-api.example.com"; got != want {
		t.Errorf("flipWords = %q, want %q", got, want)
	}
	if got := flipWords("api.example.com", []string{"prod"}); len(got) != 0 {
		t.Errorf("flipWords without a hyphen gave %q", got)
	}
	if got, want := sorted(addSuffixWords("api.example.com", []string{"v2"})),
		"api-v2.example.com apiv2.example.com"; got != want {
		t.Errorf("addSuffixWords = %q, want %q", got, want)
	}
	if got, want := sorted(addPrefixWords("api.example.com", []string{"dev"})),
		"dev-api.example.com devapi.example.com"; got != want {
		t.Errorf("addPrefixWords = %q, want %q", got, want)
	}
	if got := appendNumbers("-.example.com"); len(got) != 0 {
		t.Errorf("appendNumbers of an empty label gave %q", got)
	}
	if got := len(appendNumbers("api.example.com")); got != 20 {
		t.Errorf("appendNumbers gave %d guesses, want 20", got)
	}
}
