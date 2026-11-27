// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package schemaorg

import "testing"

const uticaProductsHomepage = `<!doctype html><html><head>
<title>Utica Products</title>
<script type="application/ld+json">
{"@context":"https://schema.org","@graph":[
  {"@type":"WebSite","name":"Utica Products","url":"https://www.utica-products.com/"},
  {"@type":"Organization","name":"Utica Products",
   "legalName":"Productos Económicos de Utica, S.A.B. de C.V.",
   "leiCode":"5493000UTICAPROD0001",
   "address":{"@type":"PostalAddress","addressCountry":"MX","addressLocality":"Monterrey"},
   "sameAs":["https://www.wikidata.org/wiki/Q100004"]}
]}
</script>
</head><body></body></html>`

func TestParseSchemaOrgGraph(t *testing.T) {
	c, ok := parseSchemaOrg([]byte(uticaProductsHomepage))
	if !ok {
		t.Fatal("expected an organization")
	}
	if c.Name != "Utica Products" || c.BestName() != "Productos Económicos de Utica, S.A.B. de C.V." {
		t.Errorf("name=%q best=%q", c.Name, c.BestName())
	}
	if c.Country != "MX" || c.LEI != "5493000UTICAPROD0001" {
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
		if c, ok := parseSchemaOrg([]byte(html)); ok || c.BestName() != "" {
			t.Errorf("expected none for %q, got %+v", html, c)
		}
	}
}
