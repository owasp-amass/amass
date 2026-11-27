// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package shodan reverse-searches Shodan for the origin hosts that serve a
// fingerprint the organization already has. On a fingerprint Identifier
// (favicon_mmh3 or JARM) carried by an in-scope host, it asks Shodan which IPs
// serve the same value — candidate origins behind a CDN/WAF — and records each
// as an IPAddress with Shodan provenance, then enqueues it for Amass's own
// service discovery to probe (ai-design-principles.md, principle 10;
// reverse-search-collectors-spec.md).
package shodan

import (
	"net/url"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/reversesearch"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
)

// searchURL is the Shodan host search endpoint.
const searchURL = "https://api.shodan.io/shodan/host/search"

// Source is the Shodan reverse search: an API key in the query string.
var Source = support.OriginSource{
	Name:    "Shodan",
	Query:   reversesearch.ShodanQuery,
	Request: request,
	Parse:   reversesearch.ParseShodan,
}

// NewShodan returns the Shodan reverse-search plugin.
func NewShodan() et.Plugin { return support.NewOriginSearch(Source) }

func request(query string, cred *config.Credentials) *amasshttp.Request {
	if cred.Apikey == "" {
		return nil
	}
	return &amasshttp.Request{URL: searchURL + "?key=" + url.QueryEscape(cred.Apikey) +
		"&query=" + url.QueryEscape(query)}
}
