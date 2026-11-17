// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package wikidata

import (
	"strings"
	"testing"
)

// A single entity across two rows (one adds the LEI), the way the SPARQL
// service returns multi-valued optionals.
const femsaResponse = `{
  "head": {"vars": ["item","itemLabel","legal","iso","lei","website"]},
  "results": {"bindings": [
    {
      "item":     {"type":"uri","value":"http://www.wikidata.org/entity/Q1396863"},
      "itemLabel":{"type":"literal","value":"FEMSA"},
      "legal":    {"type":"literal","value":"Fomento Económico Mexicano, S.A.B. de C.V."},
      "iso":      {"type":"literal","value":"MX"},
      "website":  {"type":"uri","value":"https://www.femsa.com/"}
    },
    {
      "item":     {"type":"uri","value":"http://www.wikidata.org/entity/Q1396863"},
      "itemLabel":{"type":"literal","value":"FEMSA"},
      "lei":      {"type":"literal","value":"8COTL657Z5I1QULT5R68"},
      "website":  {"type":"uri","value":"https://www.femsa.com/"}
    }
  ]}
}`

func TestParseSPARQLSingleEntity(t *testing.T) {
	cs, err := parseSPARQL([]byte(femsaResponse))
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 {
		t.Fatalf("got %d companies, want 1: %+v", len(cs), cs)
	}
	c := cs[0]
	if c.QID != "Q1396863" || c.Name != "FEMSA" {
		t.Errorf("qid/name = %q/%q", c.QID, c.Name)
	}
	if c.Country != "MX" || c.LEI != "8COTL657Z5I1QULT5R68" {
		t.Errorf("country/lei = %q/%q", c.Country, c.LEI)
	}
	if c.bestName() != "Fomento Económico Mexicano, S.A.B. de C.V." {
		t.Errorf("bestName = %q", c.bestName())
	}
}

// A real femsa.com response captured from the Wikidata Query Service: no
// official name (P1448), label used instead; website is the bare http host.
const femsaReal = `{
  "head" : {"vars" : [ "item", "itemLabel", "legal", "iso", "lei", "website" ]},
  "results" : {"bindings" : [ {
    "item" : {"type" : "uri","value" : "http://www.wikidata.org/entity/Q1435628"},
    "iso" : {"type" : "literal","value" : "MX"},
    "website" : {"type" : "uri","value" : "http://femsa.com/"},
    "lei" : {"type" : "literal","value" : "549300A8MDWDJNMLV153"},
    "itemLabel" : {"xml:lang" : "en","type" : "literal","value" : "FEMSA"}
  } ]}
}`

func TestParseSPARQLRealSample(t *testing.T) {
	cs, err := parseSPARQL([]byte(femsaReal))
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 {
		t.Fatalf("got %d, want 1", len(cs))
	}
	c := cs[0]
	if c.QID != "Q1435628" || c.bestName() != "FEMSA" || c.Country != "MX" ||
		c.LEI != "549300A8MDWDJNMLV153" || c.Website != "http://femsa.com/" {
		t.Fatalf("parsed %+v", c)
	}
}

func TestParseSPARQLAmbiguous(t *testing.T) {
	// Two distinct entities claim the website; the caller resolves none.
	body := `{"results":{"bindings":[
      {"item":{"type":"uri","value":"http://www.wikidata.org/entity/Q1"},"itemLabel":{"value":"Alpha"}},
      {"item":{"type":"uri","value":"http://www.wikidata.org/entity/Q2"},"itemLabel":{"value":"Beta"}}
    ]}}`
	cs, err := parseSPARQL([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 2 {
		t.Fatalf("got %d, want 2 (ambiguous)", len(cs))
	}
}

func TestParseSPARQLSkipsUnlabeled(t *testing.T) {
	// An item whose label is just its QID carries no usable name.
	body := `{"results":{"bindings":[
      {"item":{"type":"uri","value":"http://www.wikidata.org/entity/Q999"},"itemLabel":{"value":"Q999"}}
    ]}}`
	cs, err := parseSPARQL([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 0 {
		t.Fatalf("got %+v, want none", cs)
	}
}

func TestWebsiteValues(t *testing.T) {
	v := websiteValues("femsa.com")
	// Exact canonical URLs, as IRI and literal, for host and www. host.
	for _, want := range []string{
		"<https://www.femsa.com/>", `"https://femsa.com"`, "<http://femsa.com/>",
	} {
		if !strings.Contains(v, want) {
			t.Errorf("values missing %s: %q", want, v)
		}
	}
	// No regex scan: the query must not fall back to REGEX over all websites.
	if strings.Contains(buildQuery("femsa.com"), "REGEX") {
		t.Error("query must use VALUES, not REGEX")
	}
}
