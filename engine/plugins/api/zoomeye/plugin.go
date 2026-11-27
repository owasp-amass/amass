// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package zoomeye reverse-searches ZoomEye for the origin hosts that serve a
// fingerprint the organization already has. On an in-scope favicon_mmh3 or JARM
// Identifier it asks ZoomEye which hosts serve the same value and records each
// hit as an IPAddress enqueued for probing (reverse-search-collectors-spec.md).
package zoomeye

import (
	"net/url"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/reversesearch"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
)

// searchURL is the ZoomEye host search endpoint.
const searchURL = "https://api.zoomeye.org/host/search"

// Source is the ZoomEye reverse search: an API key in the API-KEY header.
var Source = support.OriginSource{
	Name:    "ZoomEye",
	Query:   reversesearch.ZoomEyeQuery,
	Request: request,
	Parse:   reversesearch.ParseZoomEye,
}

// NewZoomEye returns the ZoomEye reverse-search plugin.
func NewZoomEye() et.Plugin { return support.NewOriginSearch(Source) }

func request(query string, cred *config.Credentials) *amasshttp.Request {
	if cred.Apikey == "" {
		return nil
	}
	return &amasshttp.Request{
		URL:    searchURL + "?query=" + url.QueryEscape(query),
		Header: amasshttp.Header{"API-KEY": []string{cred.Apikey}},
	}
}
