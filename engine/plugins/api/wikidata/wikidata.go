// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package wikidata

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
)

// endpoint is the Wikidata Query Service SPARQL endpoint.
const endpoint = "https://query.wikidata.org/sparql"

// company is one organization Wikidata identifies as the entity whose official
// website (P856) is the queried domain.
type company struct {
	QID       string // Wikidata entity id, e.g. Q1396863
	Name      string // the English label (P373/rdfs:label)
	LegalName string // official name (P1448)
	Country   string // ISO 3166-1 alpha-2 of the country (P17 -> P297)
	LEI       string // Legal Entity Identifier (P1278)
	Website   string // the matched official website (P856)
}

// sparqlResponse is the Wikidata SPARQL JSON result envelope. Each binding maps
// a variable name to a typed value.
type sparqlResponse struct {
	Results struct {
		Bindings []map[string]struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"bindings"`
	} `json:"results"`
}

// websiteValues builds the SPARQL VALUES list of canonical official-website
// URLs for a domain: both schemes, with and without a trailing slash, for the
// bare host and its www. host, each as an IRI and as a string literal (the url
// datatype is an IRI in Wikidata's RDF, but the literal forms cost nothing and
// guard against representation differences). Matching exact values lets the
// query use Wikidata's P856 index instead of scanning every website statement
// (which times out and loads their service — principle 16).
func websiteValues(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	var urls []string
	for _, h := range []string{d, "www." + d} {
		for _, scheme := range []string{"https://", "http://"} {
			for _, tail := range []string{"/", ""} {
				urls = append(urls, scheme+h+tail)
			}
		}
	}
	var vals []string
	for _, u := range urls {
		vals = append(vals, "<"+u+">", `"`+u+`"`)
	}
	return strings.Join(vals, " ")
}

// buildQuery returns the SPARQL that reverse-looks-up a domain to the entity
// whose official website it is, with that entity's official name, country
// (as an ISO alpha-2 code), and LEI. It matches exact website values through
// VALUES so the P856 index is used rather than a full scan.
func buildQuery(domain string) string {
	return `SELECT ?item ?itemLabel ?legal ?iso ?lei ?website WHERE {
  VALUES ?website { ` + websiteValues(domain) + ` }
  ?item wdt:P856 ?website .
  OPTIONAL { ?item wdt:P1448 ?legal. }
  OPTIONAL { ?item wdt:P17 ?country. ?country wdt:P297 ?iso. }
  OPTIONAL { ?item wdt:P1278 ?lei. }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en". }
} LIMIT 10`
}

// qidFromURI returns the Qxxxx id from a Wikidata entity URI.
func qidFromURI(uri string) string {
	if i := strings.LastIndexByte(uri, '/'); i >= 0 {
		return uri[i+1:]
	}
	return uri
}

// queryByDomain asks Wikidata which entity's official website is the domain.
// It returns every distinct entity matched; a caller treats more than one as
// ambiguous and resolves none (principle 8: never guess between candidates).
func queryByDomain(ctx context.Context, rl interface {
	Wait(context.Context) error
}, domain string) ([]company, error) {
	u := endpoint + "?format=json&query=" + url.QueryEscape(buildQuery(domain))

	_ = rl.Wait(ctx)
	wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(wctx, amasshttp.DefaultClient, &amasshttp.Request{URL: u})
	if err != nil || resp == nil || resp.Body == "" {
		return nil, fmt.Errorf("wikidata query for %s failed: %v", domain, err)
	}
	return parseSPARQL([]byte(resp.Body))
}

// parseSPARQL reads a Wikidata SPARQL JSON response into the distinct entities
// it names, keyed by QID (a company can have several website/LEI rows).
func parseSPARQL(body []byte) ([]company, error) {
	var r sparqlResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}

	byQID := map[string]*company{}
	var order []string
	for _, b := range r.Results.Bindings {
		item, ok := b["item"]
		if !ok || item.Value == "" {
			continue
		}
		qid := qidFromURI(item.Value)
		c := byQID[qid]
		if c == nil {
			c = &company{QID: qid}
			byQID[qid] = c
			order = append(order, qid)
		}
		if v := b["itemLabel"].Value; v != "" && c.Name == "" {
			c.Name = v
		}
		if v := b["legal"].Value; v != "" && c.LegalName == "" {
			c.LegalName = v
		}
		if v := b["iso"].Value; v != "" && c.Country == "" {
			c.Country = strings.ToUpper(strings.TrimSpace(v))
		}
		if v := b["lei"].Value; v != "" && c.LEI == "" {
			c.LEI = strings.ToUpper(strings.TrimSpace(v))
		}
		if v := b["website"].Value; v != "" && c.Website == "" {
			c.Website = v
		}
	}

	out := make([]company, 0, len(order))
	for _, qid := range order {
		// An unlabeled QID (label equals the id) carries no usable name.
		c := byQID[qid]
		if c.Name == "" || strings.EqualFold(c.Name, qid) {
			continue
		}
		out = append(out, *c)
	}
	return out, nil
}

// bestName returns the name to store for the organization: the official name
// when present, else the label.
func (c company) bestName() string {
	if n := strings.TrimSpace(c.LegalName); n != "" {
		return n
	}
	return strings.TrimSpace(c.Name)
}
