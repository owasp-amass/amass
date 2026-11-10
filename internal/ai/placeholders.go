// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed semantics/placeholder_values.json
var placeholderJSON []byte

var placeholderPhrases = sync.OnceValue(func() []string {
	var data struct {
		License string   `json:"_license"`
		About   string   `json:"_about"`
		Phrases []string `json:"phrases"`
	}
	if err := decodeStrict(placeholderJSON, &data); err != nil {
		panic("placeholder_values.json: " + err.Error())
	}

	out := make([]string, 0, len(data.Phrases))
	for _, p := range data.Phrases {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}

	return out
})

// isPlaceholder reports whether an attribute value is a redaction or
// privacy-service placeholder that identifies no one.
func isPlaceholder(a Asset) bool {
	for _, s := range []string{strings.ToLower(assetLabel(a)), strings.ToLower(a.Key)} {
		if s == "" {
			continue
		}
		for _, p := range placeholderPhrases() {
			if strings.Contains(s, p) {
				return true
			}
		}
	}

	return false
}
