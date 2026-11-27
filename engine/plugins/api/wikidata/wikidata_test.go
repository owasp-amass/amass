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
const uticaProductsResponse = `{
  "head": {"vars": ["item","itemLabel","legal","iso","lei","website"]},
  "results": {"bindings": [
    {
      "item":     {"type":"uri","value":"http://www.wikidata.org/entity/Q100003"},
      "itemLabel":{"type":"literal","value":"Utica Products"},
      "legal":    {"type":"literal","value":"Productos Económicos de Utica, S.A.B. de C.V."},
      "iso":      {"type":"literal","value":"MX"},
      "website":  {"type":"uri","value":"https://www.utica-products.com/"}
    },
    {
      "item":     {"type":"uri","value":"http://www.wikidata.org/entity/Q100003"},
      "itemLabel":{"type":"literal","value":"Utica Products"},
      "lei":      {"type":"literal","value":"5493000UTICAPROD0002"},
      "website":  {"type":"uri","value":"https://www.utica-products.com/"}
    }
  ]}
}`

func TestParseSPARQLSingleEntity(t *testing.T) {
	cs, err := parseSPARQL([]byte(uticaProductsResponse))
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 {
		t.Fatalf("got %d companies, want 1: %+v", len(cs), cs)
	}
	c := cs[0]
	if c.QID != "Q100003" || c.Name != "Utica Products" {
		t.Errorf("qid/name = %q/%q", c.QID, c.Name)
	}
	if c.Country != "MX" || c.LEI != "5493000UTICAPROD0002" {
		t.Errorf("country/lei = %q/%q", c.Country, c.LEI)
	}
	if c.BestName() != "Productos Económicos de Utica, S.A.B. de C.V." {
		t.Errorf("bestName = %q", c.BestName())
	}
}

// Shaped like a real response from the Wikidata Query Service: no
// official name (P1448), label used instead; website is the bare http host.
const uticaProductsReal = `{
  "head" : {"vars" : [ "item", "itemLabel", "legal", "iso", "lei", "website" ]},
  "results" : {"bindings" : [ {
    "item" : {"type" : "uri","value" : "http://www.wikidata.org/entity/Q100004"},
    "iso" : {"type" : "literal","value" : "MX"},
    "website" : {"type" : "uri","value" : "http://utica-products.com/"},
    "lei" : {"type" : "literal","value" : "5493000UTICAPROD0001"},
    "itemLabel" : {"xml:lang" : "en","type" : "literal","value" : "Utica Products"}
  } ]}
}`

func TestParseSPARQLRealSample(t *testing.T) {
	cs, err := parseSPARQL([]byte(uticaProductsReal))
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 {
		t.Fatalf("got %d, want 1", len(cs))
	}
	c := cs[0]
	if c.QID != "Q100004" || c.BestName() != "Utica Products" || c.Country != "MX" ||
		c.LEI != "5493000UTICAPROD0001" || c.Website != "http://utica-products.com/" {
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
	v := websiteValues("utica-products.com")
	// Exact canonical URLs, as IRI and literal, for host and www. host.
	for _, want := range []string{
		"<https://www.utica-products.com/>", `"https://utica-products.com"`, "<http://utica-products.com/>",
	} {
		if !strings.Contains(v, want) {
			t.Errorf("values missing %s: %q", want, v)
		}
	}
	// No regex scan: the query must not fall back to REGEX over all websites.
	if strings.Contains(buildQuery("utica-products.com"), "REGEX") {
		t.Error("query must use VALUES, not REGEX")
	}
}
