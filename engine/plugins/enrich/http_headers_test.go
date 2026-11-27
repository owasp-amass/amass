// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"strings"
	"testing"
)

// A response's headers name the hosts its CSP loads content from, the
// origins CORS and frame-ancestors let in, its report endpoints and internal
// names proxy headers leak; keywords, schemes, wildcards, IP addresses and
// private names name nothing.
func TestParseHeaderRefs(t *testing.T) {
	refs := parseHeaderRefs(map[string][]string{
		"Content-Security-Policy": {"default-src 'self'; script-src 'self' 'nonce-abc' https://www.googletagmanager.com " +
			"*.google-analytics.com cdn.example.edu:443 data: blob: https: *; frame-ancestors 'self' " +
			"https://portal.example-sister.org; report-uri https://example.report-uri.com/r/d/csp/enforce"},
		"content-security-policy-report-only": {"connect-src https://api.segment.io wss://ws.pusher.com"},
		"Access-Control-Allow-Origin":         {"https://apply.example-sister.org"},
		"Report-To": {`{"group":"default","max_age":31536000,"endpoints":[{"url":"https://o1.ingest.sentry.io/api/1/security/"}]}, ` +
			`{"group":"nel","endpoints":[{"url":"https://nel.example.net/report"}]}`},
		"Reporting-Endpoints": {`csp="https://csp.example.net/r", default="https://reports.example.net/"`},
		"Via":                 {"1.1 varnish, 1.1 proxy1.int.example.edu (squid/4.10)"},
		"X-Backend-Server":    {"web03.example.edu"},
		"X-Served-By":         {"cache-iad-kiad7000037-IAD"},
		"X-Server":            {"10.0.0.5", "intranet.corp"},
	})

	join := func(s []string) string { return strings.Join(s, ",") }
	if got := join(refs.contentSources); got != "www.googletagmanager.com,google-analytics.com,cdn.example.edu,"+
		"api.segment.io,ws.pusher.com" {
		t.Errorf("content sources %s", got)
	}
	if got := join(refs.allowedOrigins); got != "portal.example-sister.org,apply.example-sister.org" {
		t.Errorf("allowed origins %s", got)
	}
	var reports []string
	for _, u := range refs.reportEndpoints {
		reports = append(reports, u.Raw)
	}
	for _, want := range []string{"https://example.report-uri.com/r/d/csp/enforce", "https://o1.ingest.sentry.io/api/1/security/",
		"https://nel.example.net/report", "https://csp.example.net/r", "https://reports.example.net/"} {
		if !strings.Contains(join(reports), want) {
			t.Errorf("report endpoints %v lack %s", reports, want)
		}
	}
	if len(reports) != 5 {
		t.Errorf("report endpoints %v", reports)
	}
	if got := join(refs.leaked); got != "proxy1.int.example.edu,web03.example.edu" {
		t.Errorf("leaked names %s", got)
	}

	if !parseHeaderRefs(map[string][]string{"Content-Security-Policy": {"default-src 'none'"}}).empty() {
		t.Error("a policy naming no host gave references")
	}
}

func TestSourceHost(t *testing.T) {
	for src, want := range map[string]string{
		"https://cdn.example.com/js/": "cdn.example.com", "*.example.com": "example.com",
		"https://*.example.com:*": "example.com", "example.com:8443": "example.com", "'self'": "",
		"'sha256-abc='": "", "https:": "", "data:": "", "*": "", "null": "", "https://192.0.2.1": "",
		"localhost": "", "host.local": "",
	} {
		if got := sourceHost(src); got != want {
			t.Errorf("sourceHost(%q) = %q, want %q", src, got, want)
		}
	}
}
