// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import "testing"

func TestHostName(t *testing.T) {
	for in, want := range map[string]string{
		" WWW.Example.COM. ":   "www.example.com",
		"example.co.uk":        "example.co.uk",
		"site.github.io":       "site.github.io",
		"co.uk":                "",
		"com":                  "",
		"localhost":            "",
		"host.corp":            "",
		"printer.local":        "",
		"192.0.2.1":            "",
		"2001:db8::1":          "",
		"bad_name.example.com": "",
		"a..example.com":       "",
		"*.example.com":        "",
		"user@example.com":     "",
		"":                     "",
	} {
		if got := HostName(in); got != want {
			t.Errorf("HostName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRegistrableDomain(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":                    "example.com",
		"www.example.com":                "example.com",
		"a.b.example.co.uk":              "example.co.uk",
		"icshib.trafficmanager.net":      "trafficmanager.net",
		"live-owasp-www.pantheonsite.io": "pantheonsite.io",
		"owasp-ces.github.io":            "github.io",
		"app1.azurewebsites.net":         "azurewebsites.net",
		"co.uk":                          "",
		"host.local":                     "",
		"192.0.2.1":                      "",
	} {
		if got := RegistrableDomain(in); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
