// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enrich

import "testing"

// The Onion-Location header names the site's onion address; any spelling of
// the header counts, a value without a scheme is read as https, and a value
// that is not a .onion URL is ignored.
func TestOnionURLs(t *testing.T) {
	onion := "owaspexampleaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
	urls := onionURLs(map[string][]string{
		"Onion-Location": {"http://" + onion + "/", "http://" + onion + "/"},
		"onion-location": {onion + "/about"},
		"Location":       {"https://www.example.edu/"},
		"X-Other":        {"http://" + onion},
	})
	got := map[string]bool{}
	for _, u := range urls {
		got[u.Raw] = true
	}
	if len(urls) != 2 || !got["http://"+onion+"/"] || !got["https://"+onion+"/about"] {
		t.Errorf("onion URLs %v", got)
	}

	for _, v := range []string{"", "https://www.example.edu/", "not a url", "https://onion.example.com/"} {
		if u := extractOnionURL(v); u != nil {
			t.Errorf("extractOnionURL(%q) = %v", v, u.Raw)
		}
	}
}
