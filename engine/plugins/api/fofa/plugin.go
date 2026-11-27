// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package fofa reverse-searches FOFA for the origin hosts that serve a
// fingerprint the organization already has. On an in-scope favicon_mmh3 or JARM
// Identifier it asks FOFA which hosts serve the same value and records each hit
// as an IPAddress enqueued for probing (reverse-search-collectors-spec.md).
package fofa

import (
	"net/url"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/reversesearch"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
)

// searchURL is the FOFA search endpoint.
const searchURL = "https://fofa.info/api/v1/search/all"

// Source is the FOFA reverse search: an account email (the username) and an
// API key in the query string, with the query base-64 encoded.
var Source = support.OriginSource{
	Name:    "FOFA",
	Query:   reversesearch.FofaQueryBase64,
	Request: request,
	Parse:   reversesearch.ParseFofa,
}

// NewFOFA returns the FOFA reverse-search plugin.
func NewFOFA() et.Plugin { return support.NewOriginSearch(Source) }

func request(qb64 string, cred *config.Credentials) *amasshttp.Request {
	if cred.Username == "" || cred.Apikey == "" {
		return nil
	}
	return &amasshttp.Request{URL: searchURL + "?fields=ip,port&size=100" +
		"&email=" + url.QueryEscape(cred.Username) + "&key=" + url.QueryEscape(cred.Apikey) +
		"&qbase64=" + url.QueryEscape(qb64)}
}
