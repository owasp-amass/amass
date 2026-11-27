// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/owasp-amass/amass/v5/internal/lens"
)

// quoteSite is where a quote was found: the text around it, in lower case,
// and the quote's span within that text.
type quoteSite struct {
	text       string
	start, end int
}

// located finds the quote in the chunk and returns the text around it, where
// the names it relates must be written. ok is false when the quote is not in
// the chunk.
func located(quote, chunk string) (site quoteSite, ok bool) {
	q, text := strings.ToLower(collapse(quote)), strings.ToLower(collapse(chunk))
	if q == "" {
		return site, false
	}
	at := strings.Index(text, q)
	if at < 0 {
		return site, false
	}
	start := runeStart(text, max(0, at-quoteWindow))
	end := min(len(text), at+len(q)+quoteWindow)
	for end < len(text) && !utf8.RuneStart(text[end]) {
		end++
	}
	return quoteSite{text: text[start:end], start: at - start, end: at - start + len(q)}, true
}

// find returns where name is written near the quote: within the quote when it
// is there, otherwise its first place around it; -1 when it is not written.
func (q quoteSite) find(name string) int {
	name = strings.ToLower(name)
	if i := strings.Index(q.text[q.start:q.end], name); i >= 0 {
		return q.start + i
	}
	return strings.Index(q.text, name)
}

// has reports whether name is written near the quote.
func (q quoteSite) has(name string) bool { return q.find(name) >= 0 }

// validateAsset returns why an asset finding is rejected, or "".
func (v *docVocabulary) validateAsset(s DocumentStatement, chunk string) string {
	if s.Subject == lens.DocumentPublisher {
		return "asset: the publisher placeholder is no asset"
	}
	if !v.assetTypes[s.SubjectType] {
		return fmt.Sprintf("asset: %q is not a type documents are read for", s.SubjectType)
	}
	if reason := checkValue(s.SubjectType, s.Subject); reason != "" {
		return "asset: " + reason
	}
	site, ok := located(s.Quote, chunk)
	if !ok {
		return fmt.Sprintf("asset %s: the quote is not in the document", s.SubjectType)
	}
	if !site.has(s.Subject) {
		return fmt.Sprintf("asset %s: the value is not written where it is quoted", s.SubjectType)
	}
	return ""
}

// validateRelation returns why a relation finding is rejected, or "".
func (v *docVocabulary) validateRelation(s DocumentStatement, chunk string) string {
	if s.Subject == lens.DocumentPublisher || s.Object == lens.DocumentPublisher {
		return v.validatePublisherUnit(s, chunk)
	}
	if !v.allows(s.SubjectType, s.Predicate, s.ObjectType) {
		return fmt.Sprintf("%s does not relate %s to %s", s.Predicate, s.SubjectType, s.ObjectType)
	}
	if strings.EqualFold(s.Subject, s.Object) || len(s.Detail) > maxStatementTerm {
		return fmt.Sprintf("%s: identical ends or overlong detail", s.Predicate)
	}
	for _, end := range []struct{ typ, value string }{{s.SubjectType, s.Subject}, {s.ObjectType, s.Object}} {
		if reason := checkValue(end.typ, end.value); reason != "" {
			return s.Predicate + ": " + reason
		}
	}

	site, ok := located(s.Quote, chunk)
	if !ok {
		return fmt.Sprintf("%s: the quote is not in the document", s.Predicate)
	}
	si, oi := site.find(s.Subject), site.find(s.Object)
	if si < 0 || oi < 0 {
		return fmt.Sprintf("%s: subject or object not written where it is quoted", s.Predicate)
	}
	// a negation around the two names ("who are not sponsored by") states
	// the opposite, or nothing
	if negated(site.text, si, si+len(strings.ToLower(s.Subject)), oi, oi+len(strings.ToLower(s.Object))) {
		return fmt.Sprintf("%s: the document negates it", s.Predicate)
	}
	return ""
}

// validatePublisherUnit returns why a finding that names the document's
// publisher (lens.DocumentPublisher) is rejected, or "". The placeholder may
// only be the parent of a unit_of finding; the unit's own name must be
// written where it is quoted, and not negated there.
func (v *docVocabulary) validatePublisherUnit(s DocumentStatement, chunk string) string {
	if s.Predicate != "unit_of" || s.SubjectType != "Organization" || s.ObjectType != "Organization" ||
		s.Object != lens.DocumentPublisher || s.Subject == lens.DocumentPublisher {
		return "the publisher placeholder is only the parent of a unit_of finding"
	}
	if reason := checkValue(s.SubjectType, s.Subject); reason != "" {
		return "unit_of: " + reason
	}
	site, ok := located(s.Quote, chunk)
	if !ok {
		return "unit_of: the quote is not in the document"
	}
	si := site.find(s.Subject)
	if si < 0 {
		return "unit_of: the unit is not written where it is quoted"
	}
	end := si + len(strings.ToLower(s.Subject))
	if negated(site.text, si, end, si, end) {
		return "unit_of: the document negates it"
	}
	return ""
}

// validateAttribute returns why an attribute finding is rejected, or "".
func (v *docVocabulary) validateAttribute(s DocumentStatement, chunk string) string {
	if !slices.Contains(v.fields[s.SubjectType], s.Field) {
		return fmt.Sprintf("attribute: %s has no field %q", s.SubjectType, s.Field)
	}
	if reason := checkValue(s.SubjectType, s.Subject); reason != "" {
		return "attribute: " + reason
	}
	if s.Object == "" || len(s.Object) > maxStatementTerm {
		return fmt.Sprintf("attribute %s: empty or overlong value", s.Field)
	}
	site, ok := located(s.Quote, chunk)
	if !ok {
		return fmt.Sprintf("attribute %s: the quote is not in the document", s.Field)
	}
	if !site.has(s.Subject) || !site.has(s.Object) {
		return fmt.Sprintf("attribute %s: the asset or value is not written where it is quoted", s.Field)
	}
	return ""
}

// negationWords are the words that make a passage deny a relationship.
var negationWords = map[string]bool{"not": true, "no": true, "never": true, "neither": true, "nor": true,
	"without": true, "cannot": true, "none": true, "nonaffiliated": true, "unaffiliated": true}

// negated reports whether the text spanning two names in lower, from a little
// before the first to the end of the second, holds a negation.
func negated(lower string, s1, e1, s2, e2 int) bool {
	first, end := min(s1, s2), max(e1, e2)
	start := runeStart(lower, max(0, first-negationLead))
	// the lead stays within the sentence the first name is in
	if i := strings.LastIndexAny(lower[start:first], ".!?;"); i >= 0 {
		start += i + 1
	}
	words := strings.FieldsFunc(lower[start:end], func(r rune) bool {
		return !unicode.IsLetter(r) && r != '\'' && r != '’'
	})
	for _, w := range words {
		if negationWords[w] || strings.HasSuffix(w, "n't") || strings.HasSuffix(w, "n’t") {
			return true
		}
	}
	return false
}

// properName reports whether s reads as a name rather than a common noun
// phrase ("third parties"): it holds an uppercase letter or a digit.
func properName(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return unicode.IsUpper(r) || unicode.IsDigit(r) }) >= 0 &&
		!fragmented(s)
}

// nameParticles are the short lowercase words proper names hold: "Bank of
// America", "Universidad de la Sabana", "Ludwig van Beethoven".
var nameParticles = map[string]bool{"of": true, "de": true, "la": true, "le": true, "du": true, "da": true,
	"di": true, "do": true, "y": true, "e": true, "et": true, "en": true, "at": true, "by": true, "in": true,
	"on": true, "to": true, "an": true, "al": true, "el": true, "a": true, "i": true, "o": true}

// fragmented reports whether a name holds a piece of a word split apart when
// the document's text was extracted ("MV CC Theat er"): a lowercase word of
// one or two letters that is not a name particle.
func fragmented(s string) bool {
	for _, w := range strings.Fields(s) {
		w = strings.Trim(w, ".,;:&'\"()-")
		if w == "" || utf8.RuneCountInString(w) > 2 || strings.ToLower(w) != w ||
			strings.IndexFunc(w, func(r rune) bool { return !unicode.IsLetter(r) }) >= 0 {
			continue
		}
		if !nameParticles[w] {
			return true
		}
	}
	return false
}

// cleanText replaces the control characters extracted document text can hold
// (form feeds, NULs, escape codes) with spaces, keeping newlines and tabs. A
// model whose reply must match a JSON schema cannot copy them into a quote,
// since JSON strings forbid them raw, and the constrained reply fails partway
// through; the quotes are checked against the cleaned text, so they still
// match it verbatim.
func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || !unicode.IsControl(r) {
			return r
		}
		return ' '
	}, s)
}

// collapse trims s and joins its whitespace runs into single spaces.
func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }
