// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package censys reverse-searches Censys for the origin hosts that serve a
// fingerprint the organization already has. Censys indexes the JARM and the MD5
// favicon hash (not the mmh3 favicon Amass stores), so it acts on JARM (and a
// future favicon_md5) Identifiers carried by an in-scope host, recording each
// hit as an IPAddress enqueued for probing (reverse-search-collectors-spec.md).
package censys

import (
	"encoding/base64"
	"net/url"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/reversesearch"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
)

// searchURL is the Censys v2 hosts search endpoint.
const searchURL = "https://search.censys.io/api/v2/hosts/search"

// Source is the Censys reverse search: an API ID (the username) and secret,
// sent as basic authentication.
var Source = support.OriginSource{
	Name:    "Censys",
	Query:   reversesearch.CensysQuery,
	Request: request,
	Parse:   reversesearch.ParseCensys,
}

// NewCensys returns the Censys reverse-search plugin.
func NewCensys() et.Plugin { return support.NewOriginSearch(Source) }

func request(query string, cred *config.Credentials) *amasshttp.Request {
	if cred.Username == "" || cred.Secret == "" {
		return nil
	}
	auth := base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Secret))
	return &amasshttp.Request{
		URL:    searchURL + "?per_page=50&q=" + url.QueryEscape(query),
		Header: amasshttp.Header{"Authorization": []string{"Basic " + auth}},
	}
}
