// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	_ "embed"
	"strings"
	"sync"
	"unicode"
)

//go:embed semantics/address_terms.json
var addressTermsJSON []byte

type addressTerms struct {
	License        string            `json:"_license"`
	About          string            `json:"_about"`
	StreetTypes    map[string]string `json:"street_types"`
	Directions     map[string]string `json:"directions"`
	MaxStreetWords int               `json:"max_street_words"`
}

var loadAddressTerms = sync.OnceValue(func() addressTerms {
	var t addressTerms
	if err := decodeStrict(addressTermsJSON, &t); err != nil {
		panic("address_terms.json: " + err.Error())
	}
	if len(t.StreetTypes) == 0 || t.MaxStreetWords < 1 {
		panic("address_terms.json: street_types and max_street_words are required")
	}

	return t
})

// addressKey reduces a street address to "number street|postal" so that two
// sources' spellings of one address compare equal, or returns "" when the
// address has no street number and recognized street type.
func addressKey(address, postal string) string {
	t := loadAddressTerms()
	words := addressWords(address)

	for i, w := range words {
		if !isStreetNumber(w) {
			continue
		}

		var street []string
		for j := i + 1; j < len(words) && len(street) <= t.MaxStreetWords; j++ {
			w := words[j]
			if d, ok := t.Directions[w]; ok {
				street = append(street, d)
				continue
			}
			if st, ok := t.StreetTypes[w]; ok && len(street) > 0 {
				street = append(street, st)
				if p := postalPrefix(postal, words); p != "" {
					return words[i] + " " + strings.Join(street, " ") + "|" + p
				}
				return ""
			}
			street = append(street, w)
		}
	}

	return ""
}

// addressWords lowercases an address and splits it into words without
// punctuation.
func addressWords(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-'
	})
}

// isStreetNumber reports whether w is a building number such as 5801 or
// 12a, not a ZIP code following a box or a year.
func isStreetNumber(w string) bool {
	if w == "" || len(w) > 6 || !unicode.IsDigit(rune(w[0])) {
		return false
	}
	digits := 0
	for _, r := range w {
		if unicode.IsDigit(r) {
			digits++
		} else if !unicode.IsLetter(r) {
			return false
		}
	}

	return digits >= 1 && digits <= 5
}

// postalPrefix is the first three characters of the postal code, from the
// parsed field or the last code-like word of the address.
func postalPrefix(postal string, words []string) string {
	code := strings.ToLower(strings.TrimSpace(postal))
	if code == "" {
		for i := len(words) - 1; i >= 0; i-- {
			if isPostalCode(words[i]) {
				code = words[i]
				break
			}
		}
	}

	code = strings.ReplaceAll(strings.ReplaceAll(code, " ", ""), "-", "")
	if len(code) < 3 {
		return ""
	}

	return code[:3]
}

// isPostalCode reports whether w looks like a US ZIP code (12222 or
// 12222-1000).
func isPostalCode(w string) bool {
	base, _, _ := strings.Cut(w, "-")
	if len(base) != 5 {
		return false
	}
	for _, r := range base {
		if !unicode.IsDigit(r) {
			return false
		}
	}

	return true
}

// locationAddressKey is addressKey for a stored Location asset.
func locationAddressKey(a Asset) string {
	if a.Type != "Location" {
		return ""
	}

	addr := contentString(a, "address")
	if num, street := contentString(a, "building_number"), contentString(a, "street_name"); num != "" && street != "" {
		if k := addressKey(num+" "+street+" "+addr, contentString(a, "postal_code")); k != "" {
			return k
		}
	}

	return addressKey(addr, contentString(a, "postal_code"))
}
