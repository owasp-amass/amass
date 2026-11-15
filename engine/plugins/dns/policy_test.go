// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"strings"
	"testing"
)

// Every policy name cites the standard or vendor documentation that names
// it, and is written as labels below the apex.
func TestPolicyNamesCiteSources(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range PolicyNames {
		switch {
		case p.Label == "" || p.Label != strings.ToLower(p.Label) || strings.HasPrefix(p.Label, ".") ||
			strings.HasSuffix(p.Label, "."):
			t.Errorf("%q must be lower-case labels without a leading or trailing dot", p.Label)
		case !strings.HasPrefix(p.Source, "https://"):
			t.Errorf("%s must cite its source", p.Label)
		case p.Purpose == "":
			t.Errorf("%s must say what it holds", p.Label)
		case seen[p.Label]:
			t.Errorf("%s is listed twice", p.Label)
		}

		seen[p.Label] = true
	}
}
