// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package wikidata

import (
	"slices"
	"testing"
)

// Shaped like a real wbsearchentities response.
func TestParseWikidataQID(t *testing.T) {
	body := `{"searchinfo":{"search":"SUNY Polytechnic Institute"},"search":[
      {"id":"Q100001","label":"SUNY Polytechnic Institute","description":"public university in Utica, NY, USA"},
      {"id":"Q100002","label":"SUNY Poly College of Engineering"}
    ],"success":1}`
	if got := parseWikidataQID(body); got != "Q100001" {
		t.Errorf("qid = %q, want Q100001 (top match)", got)
	}
	if got := parseWikidataQID(`{"search":[]}`); got != "" {
		t.Errorf("empty search should yield \"\", got %q", got)
	}
	if got := parseWikidataQID("not json"); got != "" {
		t.Errorf("bad json should yield \"\", got %q", got)
	}
}

// Shaped like a real Special:EntityData/<QID>.json response (P856 value is a URL string).
func TestParseOfficialWebsites(t *testing.T) {
	body := `{"entities":{"Q364":{"claims":{"P856":[
      {"mainsnak":{"datavalue":{"value":"https://github.com","type":"string"}}},
      {"mainsnak":{"datavalue":{"value":"https://github.com","type":"string"}}}
    ]}}}}`
	got := parseOfficialWebsites(body, "Q364")
	if !slices.Equal(got, []string{"https://github.com"}) {
		t.Errorf("websites = %v, want [https://github.com] (deduped)", got)
	}
	if got := parseOfficialWebsites(body, "Q999"); got != nil {
		t.Errorf("missing qid should yield nil, got %v", got)
	}
	if got := parseOfficialWebsites(`{"entities":{"Q1":{"claims":{}}}}`, "Q1"); got != nil {
		t.Errorf("no P856 should yield nil, got %v", got)
	}
}

func TestURLHost(t *testing.T) {
	if h := urlHost("https://github.com/foo?x=1"); h != "github.com" {
		t.Errorf("host = %q, want github.com", h)
	}
	if h := urlHost("::not a url"); h != "" {
		t.Errorf("bad url should yield \"\", got %q", h)
	}
}
