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

// cloudFixture is a graph whose subject has two names on a cloud provider's
// published range (with region and service) and one name on its own space.
func cloudFixture() graphtest.VendorGraph {
	g := graphtest.VendorFixture()
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	a := func(from, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-a-" + to, FromID: from, ToID: to, Label: "dns_record",
			Type: "BasicDNSRelation", Content: map[string]any{"header": map[string]any{"rr_type": 1}}})
	}

	add("org-aws", "Organization", "org-aws", map[string]any{"name": "Amazon Web Services"})
	add("nb-cloud", "Netblock", "52.95.0.0/16", map[string]any{"cidr": "52.95.0.0/16"})
	link("nb-cloud", "provider", "org-aws")
	g.EvidenceByID = map[string][]graph.Evidence{
		"nb-cloud": {graphtest.SimpleProp("cloud_region", "us-east-1"), graphtest.SimpleProp("cloud_service", "S3")},
	}

	for i, n := range []string{"api.colgate.edu", "cdn2.colgate.edu"} {
		add(n, "FQDN", n, map[string]any{"name": n})
		ip := []string{"ip-c1", "ip-c2"}[i]
		addr := []string{"52.95.1.1", "52.95.2.2"}[i]
		add(ip, "IPAddress", addr, map[string]any{"address": addr})
		link("colgate.edu", "node", n)
		a(n, ip)
		link("nb-cloud", "contains", ip)
	}

	return g
}

func TestFindCloud(t *testing.T) {
	g := cloudFixture()
	catalog := graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}

	r, err := FindCloud(context.Background(), g, catalog, g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if len(r.Providers) != 1 {
		t.Fatalf("providers = %+v", r.Providers)
	}
	p := r.Providers[0]
	if !strings.EqualFold(p.Provider, "Amazon Web Services") || p.Names != 2 {
		t.Errorf("provider = %+v", p)
	}
	if strings.Join(p.Regions, ",") != "us-east-1" || strings.Join(p.Services, ",") != "S3" {
		t.Errorf("region/service = %+v", p)
	}
	if strings.Join(p.Networks, ",") != "52.95.0.0/16" {
		t.Errorf("networks = %+v", p)
	}
	if r.OnCloud != 2 {
		t.Errorf("on_cloud = %d (names %d, resolving %d)", r.OnCloud, r.Names, r.Resolving)
	}

	text := r.Text()
	for _, want := range []string{"2 of", "name(s) on a recognized provider", "regions: us-east-1", "services: S3"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

// TestFindCloudNone reports no provider when nothing resolves into a
// recognized range.
func TestFindCloudNone(t *testing.T) {
	g := graphtest.VendorFixture()
	catalog := graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}

	r, err := FindCloud(context.Background(), g, catalog, g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Providers) != 0 || r.OnCloud != 0 {
		t.Errorf("expected no cloud providers, got %+v (on_cloud %d)", r.Providers, r.OnCloud)
	}
	if !strings.Contains(r.Text(), "No name resolves into a recognized cloud") {
		t.Errorf("unexpected text:\n%s", r.Text())
	}
}
