// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

func TestArchiveURLRules(t *testing.T) {
	r := ArchiveURLs()
	if r.MaxURLsPerDomain <= 0 {
		t.Fatalf("max_urls_per_domain = %d", r.MaxURLsPerDomain)
	}

	for p, want := range map[string]bool{
		"/img/logo.PNG":         true,
		"/static/site.css":      true,
		"/fonts/a.woff2":        true,
		"/app/main.js":          false,
		"/docs/handbook.pdf":    false,
		"/login.php":            false,
		"/":                     false,
		"/api/v1/users":         false,
		"/download.png/details": false,
	} {
		if got := r.IsStaticPath(p); got != want {
			t.Errorf("IsStaticPath(%q) = %v, want %v", p, got, want)
		}
	}
}
