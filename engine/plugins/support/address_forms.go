// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"unicode"

	"github.com/owasp-amass/amass/v5/internal/semantics"
)

type addressForm struct {
	Name      string            `json:"name"`
	Part      string            `json:"part"`
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
	License   string         `json:"_license"`
	About     string         `json:"_about"`
	Forms     []addressForm  `json:"forms"`
	Postcodes []postcodeForm `json:"postcodes"`
}

var loadAddressForms = sync.OnceValue(func() addressForms {
	var f addressForms
	if err := json.Unmarshal(semantics.File("address_forms.json"), &f); err != nil {
		panic("address_forms.json: " + err.Error())
	}
	for _, form := range f.Forms {
		if !strings.HasPrefix(form.Source, "https://") || len(form.Countries) == 0 || len(form.Words) == 0 {
			panic(fmt.Sprintf("address_forms.json: %s needs countries, words and an https source", form.Name))
		}
		switch form.Part {
		case "suffix", "directional", "unit", "number", "po_box":
		default:
			panic(fmt.Sprintf("address_forms.json: %s has unknown part %q", form.Name, form.Part))
		}
	}
	for _, p := range f.Postcodes {
		if p.Country == "" || p.Digits <= 0 || !strings.HasPrefix(p.Source, "https://") {
			panic("address_forms.json: a postcode form needs a country, digits and an https source")
		}
	}

	return f
})

// words returns the standard forms of one kind of address word for a
// country, merged across the sets that apply to it.
func (f addressForms) words(part, country string) map[string]string {
	out := map[string]string{}
	for _, form := range f.Forms {
		if form.Part == part && slices.Contains(form.Countries, strings.ToUpper(country)) {
			for k, v := range form.Words {
				out[k] = v
			}
		}
	}

	return out
}

// cleanAddressPart lowercases a part, turns punctuation into spaces and
// collapses the spacing, keeping '#' as a word of its own.
func cleanAddressPart(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r == '#':
			b.WriteString(" # ")
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		default:
			b.WriteRune(' ')
		}
	}

	return strings.Join(strings.Fields(b.String()), " ")
}

// standardStreet puts a street in standard form for its country: number
// words become figures, a directional at either end is abbreviated when
// other words remain (a directional that is the whole name is spelled out),
// and the suffix is abbreviated.
func standardStreet(street, country string) string {
	f := loadAddressForms()
	words := strings.Fields(cleanAddressPart(street))
	if len(words) == 0 {
		return ""
	}

	numbers := f.words("number", country)
	for i, w := range words {
		if n, ok := numbers[w]; ok {
			words[i] = n
		}
	}

	dirs := f.words("directional", country)
	last := len(words) - 1
	if d, ok := dirs[words[last]]; ok && len(words) > 2 {
		words[last] = d
		last--
	}
	if d, ok := dirs[words[0]]; ok && last > 1 {
		words[0] = d
	}

	if s, ok := f.words("suffix", country)[words[last]]; ok && last > 0 {
		words[last] = s
	}

	return strings.Join(words, " ")
}

// standardUnit puts a unit in standard form: designators abbreviated, and a
// '#' dropped when a designator names the unit.
func standardUnit(unit, country string) string {
	designators := loadAddressForms().words("unit", country)
	standard := map[string]bool{}
	for _, v := range designators {
		standard[v] = true
	}

	var out []string
	named := false
	for _, w := range strings.Fields(cleanAddressPart(unit)) {
		if d, ok := designators[w]; ok {
			w = d
		}
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
	for k, v := range loadAddressForms().words("po_box", country) {
		if box == k || strings.HasPrefix(box, k+" ") {
			return v + box[len(k):]
		}
	}

	return box
}

// standardPostcode puts a postal code in standard form: uppercase, hyphens
// as spaces, and only the first digits where the country's form says so.
func standardPostcode(code, country string) string {
	code = strings.ToUpper(strings.Join(strings.Fields(strings.ReplaceAll(code, "-", " ")), " "))
	for _, p := range loadAddressForms().Postcodes {
		if strings.EqualFold(p.Country, country) {
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

	return code
}
