// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
	"unicode"
)

//go:embed jurisdictions.json
var jurisdictionsJSON []byte

type jurisdictionCatalog struct {
	License string            `json:"_license"`
	About   string            `json:"_about"`
	Codes   map[string]string `json:"codes"`
}

var loadJurisdictions = sync.OnceValue(func() map[string]string {
	var c jurisdictionCatalog
	dec := json.NewDecoder(bytes.NewReader(jurisdictionsJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("jurisdictions.json: " + err.Error())
	}
	if len(c.Codes) == 0 {
		panic("jurisdictions.json: codes are required")
	}

	codes := make(map[string]string, len(c.Codes))
	for k, v := range c.Codes {
		codes[jurisdictionKey(k)] = v
	}
	return codes
})

// jurisdictionKey folds a jurisdiction word for lookup: lower case, letters,
// digits and single spaces only ("&" kept), without a leading "state of",
// "commonwealth of" or "province of".
func jurisdictionKey(s string) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToLower(s) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '&':
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			b.WriteRune(r)
		default:
			space = true
		}
	}

	k := b.String()
	for _, p := range []string{"state of ", "commonwealth of ", "province of "} {
		k = strings.TrimPrefix(k, p)
	}
	return k
}

// JurisdictionCode returns the GLEIF-style code for a state, province or
// United Kingdom jurisdiction word ("Delaware" is "US-DE", "England and
// Wales" is "GB"), or "" for any other word. Country names are left to a
// country lookup.
func JurisdictionCode(s string) string {
	return loadJurisdictions()[jurisdictionKey(s)]
}
