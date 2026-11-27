// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func TestEvaluateHeaders(t *testing.T) {
	kinds := func(gaps []headerGap) []string {
		var out []string
		for _, g := range gaps {
			out = append(out, g.kind)
		}
		slices.Sort(out)
		return out
	}

	// A bare HTTPS response is missing every hardening header.
	bare := kinds(evaluateHeaders(map[string]string{"server": "nginx"}, nil, true))
	for _, want := range []string{HeaderNoHSTS, HeaderNoCSP, HeaderNoFrameGuard, HeaderNoSniffGuard} {
		if !slices.Contains(bare, want) {
			t.Errorf("bare HTTPS gaps = %v, want %s", bare, want)
		}
	}

	// A fully hardened response has no gaps.
	hardened := map[string]string{
		"strict-transport-security": "max-age=63072000; includesubdomains; preload",
		"content-security-policy":   "default-src 'self'; frame-ancestors 'none'",
		"x-frame-options":           "deny",
		"x-content-type-options":    "nosniff",
	}
	if g := evaluateHeaders(hardened, []string{"id=x; Path=/; Secure; HttpOnly"}, true); len(g) != 0 {
		t.Errorf("hardened gaps = %+v, want none", g)
	}

	// A CSP with frame-ancestors substitutes for X-Frame-Options.
	if g := kinds(evaluateHeaders(hardened, nil, true)); slices.Contains(g, HeaderNoFrameGuard) {
		t.Errorf("frame-ancestors should satisfy clickjacking protection: %v", g)
	}

	// HSTS is not expected on a plain-HTTP service.
	if g := kinds(evaluateHeaders(map[string]string{"server": "nginx"}, nil, false)); slices.Contains(g, HeaderNoHSTS) {
		t.Errorf("HSTS flagged on non-HTTPS service: %v", g)
	}

	// A cookie without Secure or HttpOnly is insecure.
	if g := kinds(evaluateHeaders(hardened, []string{"s=1; Path=/"}, true)); !slices.Contains(g, HeaderInsecureCookie) {
		t.Errorf("insecure cookie not flagged: %v", g)
	}
}

func TestFindHeaders(t *testing.T) {
	g := graphtest.VendorFixture()
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to, rt string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: rt})
	}

	// A bare HTTPS web service with an insecure cookie.
	add("svc-weak", "Service", map[string]any{"service_type": "web-service",
		"attributes": map[string]any{"Server": []any{"nginx"}, "Set-Cookie": []any{"sid=abc; Path=/"}}})
	add("cert-weak", "TLSCertificate", map[string]any{"serial_number": "1"})
	link("owasp.org", "port", "svc-weak", "PortRelation")
	link("svc-weak", "certificate", "cert-weak", "SimpleRelation")

	r, err := FindHeaders(context.Background(), g,
		graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if len(r.Services) != 1 || r.Services[0].Host != "owasp.org" || !r.Services[0].HTTPS {
		t.Fatalf("services = %+v", r.Services)
	}
	// Missing lists missing hardening headers only; the insecure cookie is a
	// finding, not a nameless "missing header".
	if slices.Contains(r.Services[0].Missing, "") {
		t.Errorf("Missing has an empty header name: %+v", r.Services[0].Missing)
	}
	kinds := map[string]bool{}
	for _, f := range r.Findings {
		kinds[f.Kind] = true
	}
	for _, want := range []string{HeaderNoHSTS, HeaderNoCSP, HeaderInsecureCookie} {
		if !kinds[want] {
			t.Errorf("findings = %v, want %s", r.Findings, want)
		}
	}
}
