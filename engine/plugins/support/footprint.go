// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"net/url"
	"strings"

	et "github.com/owasp-amass/amass/v5/engine/types"
)

// Footprint is the registered domains an address or URL must be in to tie
// what names it to the organization: the domain a collector searched for,
// and every domain in the enumeration's scope.
type Footprint []string

// FootprintOf is the footprint of a search for apex in e's session.
func FootprintOf(e *et.Event, apex string) Footprint {
	f := Footprint{apex}
	for _, d := range e.Session.Scope().Domains() {
		if d = strings.TrimSuffix(strings.ToLower(d), "."); d != "" && d != apex {
			f = append(f, d)
		}
	}
	return f
}

// Host returns the footprint domain a URL's host is or is under, or "".
func (f Footprint) Host(raw string) string {
	u, err := url.Parse(strings.TrimPrefix(strings.TrimSpace(raw), "git+"))
	if err != nil {
		return ""
	}
	return f.DomainOf(u.Hostname())
}

// Address returns the footprint domain an email address is at, or "".
func (f Footprint) Address(email string) string {
	email = strings.TrimSpace(email)
	at := strings.LastIndexByte(email, '@')
	if at < 1 {
		return ""
	}
	return f.DomainOf(email[at+1:])
}

// DomainOf returns the footprint domain host is or is under, or "".
func (f Footprint) DomainOf(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, d := range f {
		if host == d || strings.HasSuffix(host, "."+d) {
			return d
		}
	}
	return ""
}
