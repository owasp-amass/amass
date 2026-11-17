// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package schemaorg

import "testing"

const femsaHomepage = `<!doctype html><html><head>
<title>FEMSA</title>
<script type="application/ld+json">
{"@context":"https://schema.org","@graph":[
  {"@type":"WebSite","name":"FEMSA","url":"https://www.femsa.com/"},
  {"@type":"Organization","name":"FEMSA",
   "legalName":"Fomento Económico Mexicano, S.A.B. de C.V.",
   "leiCode":"549300A8MDWDJNMLV153",
   "address":{"@type":"PostalAddress","addressCountry":"MX","addressLocality":"Monterrey"},
   "sameAs":["https://www.wikidata.org/wiki/Q1435628"]}
]}
</script>
</head><body></body></html>`

func TestParseSchemaOrgGraph(t *testing.T) {
	c, ok := parseSchemaOrg([]byte(femsaHomepage))
	if !ok {
		t.Fatal("expected an organization")
	}
	if c.Name != "FEMSA" || c.bestName() != "Fomento Económico Mexicano, S.A.B. de C.V." {
		t.Errorf("name=%q best=%q", c.Name, c.bestName())
	}
	if c.Country != "MX" || c.LEI != "549300A8MDWDJNMLV153" {
		t.Errorf("country=%q lei=%q", c.Country, c.LEI)
	}
}

func TestParseSchemaOrgCountryObject(t *testing.T) {
	// addressCountry as a nested Country object, and the LEI via an identifier
	// PropertyValue rather than leiCode.
	html := `<script type="application/ld+json">
{"@type":"Corporation","name":"Acme",
 "address":{"addressCountry":{"@type":"Country","name":"Mexico"}},
 "identifier":{"@type":"PropertyValue","propertyID":"LEI","value":"abc123"}}
</script>`
	c, ok := parseSchemaOrg([]byte(html))
	if !ok {
		t.Fatal("expected an organization")
	}
	if c.Country != "Mexico" || c.LEI != "ABC123" {
		t.Errorf("country=%q lei=%q", c.Country, c.LEI)
	}
}

func TestParseSchemaOrgNone(t *testing.T) {
	for _, html := range []string{
		`<html><body>no markup</body></html>`,
		`<script type="application/ld+json">{"@type":"WebSite","name":"x"}</script>`,
		`<script type="application/ld+json">not json</script>`,
	} {
		if c, ok := parseSchemaOrg([]byte(html)); ok || c.bestName() != "" {
			t.Errorf("expected none for %q, got %+v", html, c)
		}
	}
}
