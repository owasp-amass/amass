// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import "testing"

func TestExtractBrandName(t *testing.T) {
	for name, want := range map[string]string{
		// Characters outside ASCII letters and digits once cut the name short.
		"at&t enterprises, llc":    "at&t enterprises",
		"société générale sa":      "société générale",
		"procter & gamble co.":     "procter & gamble",
		"(isc)² inc.":              "(isc)²",
		"google llc":               "google",
		"apple inc.":               "apple",
		"globalsign nv-sa":         "globalsign nv-sa",
		"amazon technologies, inc": "amazon technologies",
		"national grid plc":        "national grid",
		"hopkins & sons plumbing":  "hopkins & sons plumbing",
		"colgate university":       "colgate university",
		"":                         "",
	} {
		if got := ExtractBrandName(name); got != want {
			t.Errorf("ExtractBrandName(%q) = %q, want %q", name, got, want)
		}
	}
}
