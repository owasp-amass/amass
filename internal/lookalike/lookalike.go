// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package lookalike computes the registered domain names one typing mistake
// away from a domain, as the lookalike collection and lens both need.
package lookalike

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	"golang.org/x/net/publicsuffix"
)

var rulesJSON = semantics.File("lookalikes.json")

// Rules are the typo models and limits from lookalikes.json.
type Rules struct {
	License        string   `json:"_license"`
	About          string   `json:"_about"`
	TypoSource     string   `json:"typo_source"`
	KeyboardRows   []string `json:"keyboard_rows"`
	TLDs           []string `json:"tlds"`
	TLDSource      string   `json:"tld_source"`
	MinLabelLength int      `json:"min_label_length"`
	MaxCandidates  int      `json:"max_candidates"`
	adjacent       map[rune]string
}

// LoadRules returns the lookalike rules.
var LoadRules = sync.OnceValues(func() (Rules, error) {
	var r Rules
	if err := graph.DecodeStrict(rulesJSON, &r); err != nil {
		return r, fmt.Errorf("lookalikes.json: %w", err)
	}
	if len(r.KeyboardRows) == 0 || r.MinLabelLength < 1 || r.MaxCandidates < 1 ||
		!strings.HasPrefix(r.TypoSource, "https://") || !strings.HasPrefix(r.TLDSource, "https://") {
		return r, errors.New("lookalikes.json: keyboard_rows, limits and sources are required")
	}

	r.adjacent = map[rune]string{}
	for i, row := range r.KeyboardRows {
		keys := []rune(row)
		for j, k := range keys {
			var near []rune
			if j > 0 {
				near = append(near, keys[j-1])
			}
			if j+1 < len(keys) {
				near = append(near, keys[j+1])
			}
			// The keys above and below in a staggered layout.
			for _, other := range []int{i - 1, i + 1} {
				if other < 0 || other >= len(r.KeyboardRows) {
					continue
				}

				o := []rune(r.KeyboardRows[other])
				for _, x := range []int{j - 1, j, j + 1} {
					if x >= 0 && x < len(o) {
						near = append(near, o[x])
					}
				}
			}

			r.adjacent[k] = string(near)
		}
	}

	return r, nil
})

// Split returns a registered domain's first label and its public suffix.
func Split(domain string) (string, string, bool) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	reg, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil || reg != domain {
		return "", "", false
	}

	label, suffix, ok := strings.Cut(domain, ".")
	return label, suffix, ok
}

// Candidates returns the registered domains that look like domain: one
// typing mistake away from its first label under the same suffix, and the
// same label under the other suffixes in the rules, sorted and without the
// domain itself. A label shorter than the rules' minimum has none.
func (r Rules) Candidates(domain string) []string {
	label, suffix, ok := Split(domain)
	if !ok || len([]rune(label)) < r.MinLabelLength || strings.HasPrefix(label, "xn--") {
		return nil
	}

	set := map[string]bool{}
	add := func(l, s string) {
		if validLabel(l) && (l != label || s != suffix) {
			set[l+"."+s] = true
		}
	}

	keys := []rune(label)
	for i := range keys {
		// Deletion.
		add(string(keys[:i])+string(keys[i+1:]), suffix)
		// Transposition with the next character.
		if i+1 < len(keys) && keys[i] != keys[i+1] {
			t := append([]rune{}, keys...)
			t[i], t[i+1] = t[i+1], t[i]
			add(string(t), suffix)
		}
		// Substitution by an adjacent key.
		for _, k := range r.adjacent[keys[i]] {
			add(string(keys[:i])+string(k)+string(keys[i+1:]), suffix)
		}
	}
	// Insertion: a key next to either neighbor, or the previous key typed
	// twice.
	for i := 0; i <= len(keys); i++ {
		var ins []rune
		if i > 0 {
			ins = append(ins, keys[i-1])
			ins = append(ins, []rune(r.adjacent[keys[i-1]])...)
		}
		if i < len(keys) {
			ins = append(ins, []rune(r.adjacent[keys[i]])...)
		}
		for _, k := range ins {
			add(string(keys[:i])+string(k)+string(keys[i:]), suffix)
		}
	}
	for _, tld := range r.TLDs {
		add(label, tld)
	}

	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}

	sort.Strings(out)
	if len(out) > r.MaxCandidates {
		out = out[:r.MaxCandidates]
	}

	return out
}

// validLabel reports whether l can be a DNS label of a registered domain.
func validLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, c := range l {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}

	return true
}
