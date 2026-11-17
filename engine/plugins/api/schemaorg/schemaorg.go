// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package schemaorg

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
)

// company is the organization identity a homepage asserts about itself in
// schema.org JSON-LD.
type company struct {
	Name      string
	LegalName string
	Country   string // as published (ISO alpha-2 or a country name)
	LEI       string // schema.org leiCode, the exact key that bootstraps GLEIF
}

func (c company) bestName() string {
	if n := strings.TrimSpace(c.LegalName); n != "" {
		return n
	}
	return strings.TrimSpace(c.Name)
}

// ldJSONBlock matches a <script type="application/ld+json"> ... </script> block.
var ldJSONBlock = regexp.MustCompile(`(?is)<script[^>]*type\s*=\s*["']application/ld\+json["'][^>]*>(.*?)</script>`)

// fetchHomepage retrieves the apex homepage HTML, trying HTTPS then HTTP. This
// contacts the target, so the caller runs it only in active mode.
func fetchHomepage(ctx context.Context, rl interface {
	Wait(context.Context) error
}, domain string) string {
	for _, u := range []string{"https://" + domain + "/", "http://" + domain + "/"} {
		_ = rl.Wait(ctx)
		wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		resp, err := amasshttp.RequestWebPage(wctx, amasshttp.DefaultClient, &amasshttp.Request{URL: u})
		cancel()
		if err == nil && resp != nil && resp.Body != "" {
			return resp.Body
		}
	}
	return ""
}

// parseSchemaOrg extracts the organization a page declares about itself in
// schema.org JSON-LD. It returns the identity and whether an organization node
// with a usable name was found. Microdata/RDFa are not parsed (JSON-LD is the
// dominant form); unknown shapes are skipped rather than guessed.
func parseSchemaOrg(html []byte) (company, bool) {
	var out company
	for _, m := range ldJSONBlock.FindAllSubmatch(html, -1) {
		var doc any
		if err := json.Unmarshal(m[1], &doc); err != nil {
			continue
		}
		for _, node := range orgNodes(doc) {
			fill(&out, node)
			if out.Name != "" || out.LegalName != "" {
				// Prefer the first organization node that names itself.
				if out.LEI != "" || out.Country != "" || len(nodeType(node)) > 0 {
					return out, true
				}
			}
		}
	}
	return out, out.bestName() != ""
}

// orgNodes flattens a JSON-LD document (an object, an array, or a @graph) into
// the nodes whose @type is an organization kind.
func orgNodes(doc any) []map[string]any {
	var out []map[string]any
	var visit func(any)
	visit = func(v any) {
		switch t := v.(type) {
		case []any:
			for _, e := range t {
				visit(e)
			}
		case map[string]any:
			if g, ok := t["@graph"]; ok {
				visit(g)
			}
			if isOrgType(t) {
				out = append(out, t)
			}
		}
	}
	visit(doc)
	return out
}

// orgTypes are the schema.org @type values treated as an organization.
var orgTypes = map[string]bool{
	"organization": true, "corporation": true, "localbusiness": true,
	"ngo": true, "governmentorganization": true, "educationalorganization": true,
	"collegeoruniversity": true, "nonprofit": true, "onlinebusiness": true,
}

func nodeType(node map[string]any) []string {
	var types []string
	switch t := node["@type"].(type) {
	case string:
		types = append(types, t)
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				types = append(types, s)
			}
		}
	}
	return types
}

func isOrgType(node map[string]any) bool {
	for _, t := range nodeType(node) {
		lt := strings.ToLower(strings.TrimSpace(t))
		if orgTypes[lt] || strings.HasSuffix(lt, "organization") {
			return true
		}
	}
	return false
}

// fill copies the fields of interest from a node, keeping the first non-empty
// value seen across nodes.
func fill(c *company, node map[string]any) {
	if c.Name == "" {
		c.Name = asString(node["name"])
	}
	if c.LegalName == "" {
		c.LegalName = asString(node["legalName"])
	}
	if c.Country == "" {
		c.Country = country(node["address"])
	}
	if c.LEI == "" {
		c.LEI = strings.ToUpper(strings.TrimSpace(asString(node["leiCode"])))
	}
	if c.LEI == "" {
		c.LEI = identifierLEI(node["identifier"])
	}
}

// country extracts an address country from a schema.org address, which may be a
// string, a PostalAddress object (addressCountry as a string or a Country
// object), or an array of either.
func country(v any) string {
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if c := country(e); c != "" {
				return c
			}
		}
	case map[string]any:
		if ac, ok := t["addressCountry"]; ok {
			return asString(ac)
		}
	}
	return ""
}

// identifierLEI finds a Legal Entity Identifier among schema.org identifier
// PropertyValue objects (propertyID "LEI").
func identifierLEI(v any) string {
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if lei := identifierLEI(e); lei != "" {
				return lei
			}
		}
	case map[string]any:
		if strings.EqualFold(asString(t["propertyID"]), "LEI") {
			return strings.ToUpper(strings.TrimSpace(asString(t["value"])))
		}
	}
	return ""
}

// asString renders a schema.org scalar that may be a string or an object with a
// name/@value/identifier field.
func asString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case map[string]any:
		for _, k := range []string{"name", "@value", "identifier", "value"} {
			if s, ok := t[k].(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}
