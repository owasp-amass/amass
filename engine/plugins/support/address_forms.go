// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode"

	"github.com/owasp-amass/amass/v5/internal/semantics"
	pioz "github.com/pioz/countries"
	"golang.org/x/text/unicode/norm"
)

type addressForm struct {
	Name      string            `json:"name"`
	Part      string            `json:"part"`
	Position  string            `json:"position"`
	Countries []string          `json:"countries"`
	Source    string            `json:"source"`
	Words     map[string]string `json:"words"`
}

type postcodeForm struct {
	Country string `json:"country"`
	Digits  int    `json:"digits"`
	Source  string `json:"source"`
}

type addressForms struct {
	License       string            `json:"_license"`
	About         string            `json:"_about"`
	Letters       map[string]string `json:"letters"`
	LettersSource string            `json:"letters_source"`
	Forms         []addressForm     `json:"forms"`
	Postcodes     []postcodeForm    `json:"postcodes"`
}

// formsFile prefixes the errors in the address forms data.
const formsFile = "address_forms.json: "

// The parts of a street address whose words have standard forms, and where
// in the street a street type may stand.
var (
	addressParts    = []string{"street_type", "directional", "unit", "number", "po_box"}
	streetPositions = []string{"first", "last", "any", "ending"}
)

var loadAddressForms = sync.OnceValue(func() addressForms {
	var f addressForms
	if err := json.Unmarshal(semantics.File("address_forms.json"), &f); err != nil {
		panic(formsFile + err.Error())
	}
	if len(f.Letters) > 0 && !strings.HasPrefix(f.LettersSource, "https://") {
		panic(formsFile + "the letters need an https source")
	}

	for i, form := range f.Forms {
		if !strings.HasPrefix(form.Source, "https://") || len(form.Countries) == 0 || len(form.Words) == 0 {
			panic(fmt.Sprintf("%s%s needs countries, words and an https source", formsFile, form.Name))
		}
		if !slices.Contains(addressParts, form.Part) {
			panic(fmt.Sprintf("%s%s has unknown part %q", formsFile, form.Name, form.Part))
		}
		if !slices.Contains(streetPositions, form.Position) {
			panic(fmt.Sprintf("%s%s has unknown position %q", formsFile, form.Name, form.Position))
		}

		// the words are matched as cleaned text, so clean them the same way
		words := make(map[string]string, len(form.Words))
		for k, v := range form.Words {
			if k, v = cleanText(f.Letters, k), cleanText(f.Letters, v); k != "" && v != "" && k != v {
				words[k] = v
			}
		}

		f.Forms[i].Words = words
	}
	for _, p := range f.Postcodes {
		if p.Country == "" || p.Digits <= 0 || !strings.HasPrefix(p.Source, "https://") {
			panic(formsFile + "a postcode form needs a country, digits and an https source")
		}
	}

	return f
})

// words returns the standard forms of one kind of address word for a
// country, merged across the sets that apply to it, keyed by position.
func (f addressForms) words(part, country string) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, form := range f.Forms {
		if form.Part != part || !slices.Contains(form.Countries, strings.ToUpper(country)) {
			continue
		}
		if out[form.Position] == nil {
			out[form.Position] = map[string]string{}
		}
		for k, v := range form.Words {
			out[form.Position][k] = v
		}
	}

	return out
}

// merged returns the standard forms of one kind of address word for a
// country, whatever their position.
func (f addressForms) merged(part, country string) map[string]string {
	out := map[string]string{}
	for _, words := range f.words(part, country) {
		for k, v := range words {
			out[k] = v
		}
	}

	return out
}

// cleanText lowercases text, writes letters without a decomposition in
// their standard Latin form, drops the accents of Latin letters, turns
// punctuation into spaces and collapses the spacing, keeping '#' as a word
// of its own. Marks on letters of other scripts are kept: they change the
// letter.
func cleanText(letters map[string]string, s string) string {
	var b strings.Builder
	var base rune
	for _, r := range norm.NFD.String(strings.ToLower(s)) {
		mark := unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r)
		switch {
		case mark && unicode.Is(unicode.Latin, base):
		case mark:
			b.WriteRune(r)
		case letters[string(r)] != "":
			base = r
			b.WriteString(letters[string(r)])
		case r == '#':
			base = r
			b.WriteString(" # ")
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			base = r
			b.WriteRune(r)
		default:
			base = r
			b.WriteRune(' ')
		}
	}

	return norm.NFC.String(strings.Join(strings.Fields(b.String()), " "))
}

// cleanAddressPart cleans one part of an address (see cleanText).
func cleanAddressPart(s string) string {
	return cleanText(loadAddressForms().Letters, s)
}

// byLength returns the keys of words, longest first, so the longest match
// wins and the result does not depend on map order.
func byLength(words map[string]string) []string {
	keys := make([]string, 0, len(words))
	for k := range words {
		keys = append(keys, k)
	}

	slices.SortFunc(keys, func(a, b string) int {
		if d := len(b) - len(a); d != 0 {
			return d
		}

		return strings.Compare(a, b)
	})
	return keys
}

// phrase is a run of words and the words that replace it.
type phrase struct {
	words, with []string
}

// phrases returns the forms as phrases, longest first, so the longest match
// wins and the result does not depend on map order.
func phrases(forms map[string]string) []phrase {
	var out []phrase
	for _, k := range byLength(forms) {
		out = append(out, phrase{words: strings.Fields(k), with: strings.Fields(forms[k])})
	}

	slices.SortStableFunc(out, func(a, b phrase) int { return len(b.words) - len(a.words) })
	return out
}

// matchAt returns the phrase that matches words starting at i.
func matchAt(words []string, i int, ps []phrase) (phrase, bool) {
	for _, p := range ps {
		if i+len(p.words) <= len(words) && slices.Equal(words[i:i+len(p.words)], p.words) {
			return p, true
		}
	}

	return phrase{}, false
}

// replaceAny replaces each phrase wherever it stands, scanning left to right
// and not matching again inside a replacement.
func replaceAny(words []string, ps []phrase) []string {
	if len(ps) == 0 {
		return words
	}

	var out []string
	for i := 0; i < len(words); {
		if p, ok := matchAt(words, i, ps); ok {
			out = append(out, p.with...)
			i += len(p.words)
			continue
		}

		out = append(out, words[i])
		i++
	}

	return out
}

// standardStreet puts a street in standard form for its country: number
// words become figures, a directional at either end is abbreviated when
// other words remain (a directional that is the whole name is spelled out),
// and the street type and other words are written in their standard forms
// where the country places them: before the name, after it, anywhere in the
// street, or as the end of a word.
func standardStreet(street, country string) string {
	f := loadAddressForms()
	words := strings.Fields(cleanAddressPart(street))
	if len(words) == 0 {
		return ""
	}

	numbers := f.merged("number", country)
	for i, w := range words {
		if n, ok := numbers[w]; ok {
			words[i] = n
		}
	}

	var head, tail []string
	dirs := f.merged("directional", country)
	if d, ok := dirs[words[len(words)-1]]; ok && len(words) > 2 {
		tail = []string{d}
		words = words[:len(words)-1]
	}
	if d, ok := dirs[words[0]]; ok && len(words) > 2 {
		head = []string{d}
		words = words[1:]
	}

	types := f.words("street_type", country)
	if p, ok := matchAt(words, 0, phrases(types["first"])); ok && len(p.words) < len(words) {
		head = append(head, p.with...)
		words = words[len(p.words):]
	}
	for _, p := range phrases(types["last"]) {
		if n := len(words) - len(p.words); n > 0 && slices.Equal(words[n:], p.words) {
			tail = append(slices.Clone(p.with), tail...)
			words = words[:n]
			break
		}
	}

	words = replaceAny(words, phrases(types["any"]))

	endings := byLength(types["ending"])
	for i, w := range words {
		for _, end := range endings {
			if strings.HasSuffix(w, end) {
				words[i] = strings.TrimSuffix(w, end) + types["ending"][end]
				break
			}
		}
	}

	return strings.Join(slices.Concat(head, words, tail), " ")
}

// standardUnit puts a unit in standard form: designators abbreviated, and a
// '#' dropped when a designator names the unit.
func standardUnit(unit, country string) string {
	designators := loadAddressForms().merged("unit", country)
	standard := map[string]bool{}
	for _, v := range designators {
		for _, w := range strings.Fields(v) {
			standard[w] = true
		}
	}

	var out []string
	named := false
	for _, w := range replaceAny(strings.Fields(cleanAddressPart(unit)), phrases(designators)) {
		if standard[w] {
			named = true
		}
		if w == "#" && named {
			continue
		}

		out = append(out, w)
	}

	return strings.Join(out, " ")
}

// standardPOBox puts a PO box in standard form: the ways of writing
// "post office box" become the standard one.
func standardPOBox(box, country string) string {
	box = cleanAddressPart(box)

	forms := loadAddressForms().merged("po_box", country)
	for _, k := range byLength(forms) {
		if box == k || strings.HasPrefix(box, k+" ") {
			return forms[k] + box[len(k):]
		}
	}

	return box
}

var postcodePatterns sync.Map

// postcodePattern returns the country's postal code pattern, anchored, or
// nil when the country has none.
func postcodePattern(country string) *regexp.Regexp {
	if v, ok := postcodePatterns.Load(country); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}

	var re *regexp.Regexp
	if c := pioz.Get(country); c != nil && c.PostalCodeFormat != "" {
		re, _ = regexp.Compile("^(?:" + c.PostalCodeFormat + ")$")
	}

	postcodePatterns.Store(country, re)
	return re
}

// standardPostcode puts a postal code in its country's standard form. Where
// the country keeps only the first digits (a US ZIP+4 is the ZIP Code and an
// add-on), only those are kept. Otherwise the code is written the first way
// its country's postal code pattern accepts: with a space or hyphen between
// its parts, as given, without letters before its digits, or with the
// country's letters before it. A code the pattern does not accept is
// uppercased with its spacing collapsed.
func standardPostcode(code, country string) string {
	country = strings.ToUpper(country)
	code = strings.ToUpper(strings.Join(strings.Fields(code), " "))
	if code == "" {
		return ""
	}

	for _, p := range loadAddressForms().Postcodes {
		if p.Country == country {
			digits := strings.Map(func(r rune) rune {
				if unicode.IsDigit(r) {
					return r
				}

				return -1
			}, code)
			if len(digits) >= p.Digits {
				return digits[:p.Digits]
			}
		}
	}

	re := postcodePattern(country)
	if re == nil {
		return code
	}

	compact := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}

		return -1
	}, code)
	bases := []string{compact}
	if trimmed := strings.TrimLeftFunc(compact, unicode.IsLetter); trimmed != compact && trimmed != "" {
		bases = append(bases, trimmed)
	}
	if !strings.HasPrefix(compact, country) {
		bases = append(bases, country+compact)
	}

	for _, b := range bases {
		for _, sep := range []string{" ", "-"} {
			for i := len(b) - 1; i > 0; i-- {
				if c := b[:i] + sep + b[i:]; re.MatchString(c) {
					return c
				}
			}
		}
		if re.MatchString(b) {
			return b
		}
	}

	return code
}

// provinceCode returns the code of the country's subdivision the province
// names, in any language its data has, or the province as given.
// IsSubdivision reports whether code is one of the country's subdivision
// codes, such as NY for US.
func IsSubdivision(country, code string) bool {
	c := pioz.Get(country)
	if c == nil || code == "" {
		return false
	}
	for _, sub := range c.Subdivisions {
		if strings.EqualFold(sub.Code, code) {
			return true
		}
	}
	return false
}

func provinceCode(province, country string) string {
	c := pioz.Get(country)
	if c == nil || province == "" {
		return province
	}

	name := cleanAddressPart(province)
	for _, sub := range c.Subdivisions {
		if strings.EqualFold(sub.Code, province) || cleanAddressPart(sub.Name) == name {
			return sub.Code
		}
		for _, t := range sub.Translations {
			if cleanAddressPart(t) == name {
				return sub.Code
			}
		}
	}

	return province
}
