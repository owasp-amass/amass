// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func webEndpointByURL(eps []WebEndpoint, raw string) (WebEndpoint, bool) {
	for _, e := range eps {
		if e.URL == raw {
			return e, true
		}
	}
	return WebEndpoint{}, false
}

func TestFindWeb(t *testing.T) {
	g := graphtest.VendorFixture()
	add := func(id, raw string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "URL", Key: raw, Content: map[string]any{"url": raw}}
	}
	link := func(from, label, to, rt string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: rt})
	}

	// The organization's website and an off-domain social profile.
	add("u-www", "https://www.colgate.edu/")
	add("u-social", "https://twitter.com/colgate")
	link("colgate", "website", "u-www", "SimpleRelation")
	link("colgate", "social_media_profile", "u-social", "SimpleRelation")
	link("u-www", "domain", "www.colgate.edu", "SimpleRelation")
	link("u-www", "ip_address", "ip-cdn", "SimpleRelation")

	// WordPress asset URLs on the site, reached because their domain is owned.
	for i, raw := range []string{
		"https://www.colgate.edu/wp-includes/js/jquery/jquery.min.js?ver=3.4.1",
		"https://www.colgate.edu/wp-includes/js/wp-embed.min.js?ver=6.5.2",
		"https://www.colgate.edu/wp-content/themes/astra/style.css?ver=4.6.1",
	} {
		id := "u-wp" + string(rune('a'+i))
		add(id, raw)
		link(id, "domain", "www.colgate.edu", "SimpleRelation")
	}

	r, err := FindWeb(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if r.Total < 5 {
		t.Fatalf("total URLs = %d (%+v)", r.Total, r)
	}
	// The website and WordPress URLs are on an owned domain.
	www, ok := webEndpointByURL(r.Endpoints, "https://www.colgate.edu/")
	if !ok {
		t.Fatalf("the website is not an owned-domain endpoint: %+v", r.Endpoints)
	}
	if www.Host != "www.colgate.edu" || www.Scheme != "https" {
		t.Errorf("website endpoint = %+v", www)
	}
	if len(www.Addresses) == 0 {
		t.Errorf("website endpoint has no stored address: %+v", www)
	}
	// The social profile is off-domain.
	if _, ok := webEndpointByURL(r.External, "https://twitter.com/colgate"); !ok {
		t.Errorf("social profile not classified off-domain: %+v", r.External)
	}
	// WordPress is recognized on the site.
	var wp *WebApplication
	for i := range r.Applications {
		if r.Applications[i].Product == "WordPress" {
			wp = &r.Applications[i]
		}
	}
	if wp == nil || wp.Site != "https://www.colgate.edu" {
		t.Fatalf("WordPress not recognized: %+v", r.Applications)
	}

	text := r.Text()
	for _, want := range []string{"Web presence of", "Endpoints on its own domains", "WordPress"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

// TestFindWebEmpty reports nothing when no URL is controlled.
func TestFindWebEmpty(t *testing.T) {
	g := graphtest.VendorFixture()
	r, err := FindWeb(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 0 || len(r.Endpoints) != 0 {
		t.Errorf("expected no web presence, got %+v", r)
	}
	if !strings.Contains(r.Text(), "No stored URL") {
		t.Errorf("unexpected text:\n%s", r.Text())
	}
}
