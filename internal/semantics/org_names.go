// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode"

	"github.com/adrg/strutil/metrics"
	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

//go:embed org_names.json
var orgNamesJSON []byte

type orgNameCatalog struct {
	License            string            `json:"_license"`
	About              string            `json:"_about"`
	LegalForms         []string          `json:"legal_forms"`
	GovernancePrefixes []string          `json:"governance_prefixes"`
	Abbreviations      map[string]string `json:"abbreviations"`
	GenericWords       []string          `json:"generic_words"`
	InitialsStopWords  []string          `json:"initials_stop_words"`
	NearSimilarity     float64           `json:"near_similarity"`
	NearMinLength      int               `json:"near_min_length"`
}

type orgNameRules struct {
	legalForms    map[string]bool
	prefixes      [][]string // tokenized, longest first
	abbreviations map[string]string
	generic       map[string]bool
	genericList   []string
	stopWords     []string
	near          float64
	minLength     int
}

var loadOrgNames = sync.OnceValue(func() orgNameRules {
	var c orgNameCatalog
	dec := json.NewDecoder(bytes.NewReader(orgNamesJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("org_names.json: " + err.Error())
	}
	if len(c.LegalForms) == 0 || len(c.GenericWords) == 0 || c.NearSimilarity <= 0 || c.NearSimilarity > 1 ||
		c.NearMinLength < 1 {
		panic("org_names.json: legal_forms, generic_words, near_similarity in (0, 1] and near_min_length are required")
	}

	r := orgNameRules{legalForms: map[string]bool{}, abbreviations: map[string]string{}, generic: map[string]bool{},
		near: c.NearSimilarity, minLength: c.NearMinLength}
	for _, f := range c.LegalForms {
		if f = normLegalForm(f); f != "" {
			r.legalForms[f] = true
		}
	}
	for _, p := range c.GovernancePrefixes {
		if toks := strings.Fields(strings.ToLower(strings.TrimSpace(p))); len(toks) > 0 {
			r.prefixes = append(r.prefixes, toks)
		}
	}
	sort.SliceStable(r.prefixes, func(i, j int) bool { return len(r.prefixes[i]) > len(r.prefixes[j]) })
	for k, v := range c.Abbreviations {
		r.abbreviations[strings.ToLower(k)] = strings.ToLower(v)
	}
	for _, w := range c.GenericWords {
		w = strings.ToLower(w)
		r.generic[w] = true
		r.genericList = append(r.genericList, w)
	}
	for _, w := range c.InitialsStopWords {
		r.stopWords = append(r.stopWords, strings.ToLower(w))
	}
	return r
})

func normLegalForm(s string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(s)), ".,")
}

// IsOrgLegalForm reports whether a word, or a two-word phrase such as
// "pty ltd", is a legal form (Inc, LLC, GmbH, S.A.).
func IsOrgLegalForm(s string) bool {
	return loadOrgNames().legalForms[normLegalForm(s)]
}

// OrgGenericWords returns the words too common in organization names to tie
// two of them together ("university", "services", "holdings").
func OrgGenericWords() []string {
	return slices.Clone(loadOrgNames().genericList)
}

// OrgInitialsStopWords returns the words skipped when a name's initials are
// taken ("of", "the", "and").
func OrgInitialsStopWords() []string {
	return slices.Clone(loadOrgNames().stopWords)
}

// IsOrgGenericWord reports whether a lower-case word is one of the generic
// words.
func IsOrgGenericWord(w string) bool {
	return loadOrgNames().generic[w]
}

// foldAccents returns a new transformer that removes accents. A chained
// transformer keeps state between calls, so each use needs its own; sharing
// one across goroutines corrupts its buffers.
func foldAccents() transform.Transformer {
	return transform.Chain(norm.NFKD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
}

// OrgNameKey returns the form organization names are compared in: folded to
// plain lower case, with "&" read as "and", abbreviations written out, a
// leading governance wrapper and trailing legal forms removed, and words
// joined by single spaces. It returns "" for a name with no words. A
// governance wrapper or legal form is never the whole key.
func OrgNameKey(name string) string {
	r := loadOrgNames()

	folded, _, err := transform.String(foldAccents(), name)
	if err != nil {
		folded = name
	}
	words := strings.FieldsFunc(strings.ToLower(folded), func(c rune) bool {
		return unicode.IsSpace(c) || c == ','
	})
	out := words[:0]
	for _, w := range words {
		w = strings.Trim(w, ".,;:()\"'")
		switch {
		case w == "":
			continue
		case w == "&":
			w = "and"
		case r.abbreviations[w] != "":
			w = r.abbreviations[w]
		}
		out = append(out, w)
	}
	words = out

	for _, p := range r.prefixes {
		if len(words) > len(p) && slices.Equal(words[:len(p)], p) {
			words = words[len(p):]
			break
		}
	}

	for len(words) > 1 {
		if n := len(words); n > 2 && r.legalForms[normLegalForm(words[n-2]+" "+words[n-1])] {
			words = words[:n-2]
			continue
		}
		if r.legalForms[normLegalForm(words[len(words)-1])] {
			words = words[:len(words)-1]
			continue
		}
		break
	}

	return strings.Join(words, " ")
}

// OrgNameMatch compares two organization names by their keys: exact when the
// keys are equal, near when the keys have the same number of words that pair
// one to one, each pair equal or close enough to be a misspelling, with at
// least one distinctive word. A name that only contains
// the other is neither.
func OrgNameMatch(a, b string) (exact, near bool) {
	ka, kb := OrgNameKey(a), OrgNameKey(b)
	if ka == "" || kb == "" {
		return false, false
	}
	if ka == kb {
		return true, false
	}
	return false, nearKeys(strings.Fields(ka), strings.Fields(kb))
}

// SameOrgName reports whether two organization names are the same
// organization's: an exact or near OrgNameMatch.
func SameOrgName(a, b string) bool {
	exact, near := OrgNameMatch(a, b)
	return exact || near
}

func nearKeys(wa, wb []string) bool {
	r := loadOrgNames()
	if len(wa) != len(wb) {
		return false
	}

	distinctive := false
	for _, w := range wa {
		if !r.generic[w] {
			distinctive = true
			break
		}
	}
	if !distinctive {
		return false
	}

	// Equal words pair first; each remaining word must pair with a remaining
	// word of the other name as a misspelling.
	rest := slices.Clone(wb)
	var unpaired []string
	for _, w := range wa {
		if i := slices.Index(rest, w); i >= 0 {
			rest = slices.Delete(rest, i, i+1)
			continue
		}
		unpaired = append(unpaired, w)
	}

	jw := metrics.NewJaroWinkler()
	jw.CaseSensitive = false
	for _, w := range unpaired {
		best, score := -1, 0.0
		for i, o := range rest {
			if !misspellable(w, r) || !misspellable(o, r) {
				continue
			}
			if s := jw.Compare(w, o); s >= r.near && s > score {
				best, score = i, s
			}
		}
		if best < 0 {
			return false
		}
		rest = slices.Delete(rest, best, best+1)
	}
	return true
}

// misspellable reports whether a word may differ from its pair by a typo: a
// word of letters only, long enough that a one-letter difference is not a
// different word.
func misspellable(w string, r orgNameRules) bool {
	if len([]rune(w)) < r.minLength {
		return false
	}
	for _, c := range w {
		if !unicode.IsLetter(c) {
			return false
		}
	}
	return true
}

// OrgNameMatchesLabel reports whether a domain label spells an organization's
// name, given as its words: the leading words written together are the label
// (owasp, uticauniversity) or begin it (utica products in
// uticaproductsus), or the label is their initials (owasp for Open Worldwide
// Application Security Project, upc for Utica Products Corporation), or
// their initials followed by a last word in full (uproducts for Utica
// Products). The leading words must include a word that is not generic,
// a label they begin must be at least five letters long, and initials at
// least three.
func OrgNameMatchesLabel(words []string, label string) bool {
	if label == "" {
		return false
	}
	r := loadOrgNames()

	var compact, all, skipped strings.Builder
	distinctive := false
	for k, w := range words {
		w = strings.Map(func(c rune) rune {
			if unicode.IsLetter(c) || unicode.IsDigit(c) {
				return c
			}

			return -1
		}, strings.ToLower(w))
		if w == "" {
			continue
		}
		if !r.generic[w] {
			distinctive = true
			// The leading words' initials and this word in full: uproducts
			// for Utica Products.
			if k > 0 && len(w) >= 4 && (all.String()+w == label || skipped.String()+w == label) {
				return true
			}
		}

		compact.WriteString(w)
		all.WriteByte(w[0])
		if !slices.Contains(r.stopWords, w) {
			skipped.WriteByte(w[0])
		}
		if !distinctive {
			continue
		}

		c := compact.String()
		if c == label || (len(c) >= 5 && strings.HasPrefix(label, c)) {
			return true
		}
		if k > 0 && len(label) >= 3 && (all.String() == label || skipped.String() == label) {
			return true
		}
	}

	return false
}
