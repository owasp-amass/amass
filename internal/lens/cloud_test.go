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

// dropLink removes a relation (by its "from-label-to" ID) from a fixture, so a
// test can isolate the hosting it cares about from the base fixture's own.
func dropLink(g graphtest.VendorGraph, id string) graphtest.VendorGraph {
	kept := make([]graph.Relation, 0, len(g.Links))
	for _, l := range g.Links {
		if l.ID != id {
			kept = append(kept, l)
		}
	}
	g.Links = kept
	return g
}

// cloudFixture is a graph whose subject has two names on a cloud provider's
// published range (with region and service) and one name on its own space.
// The base fixture's Fastly-fronted www name is removed so the test isolates
// the provider-edge path.
func cloudFixture() graphtest.VendorGraph {
	g := dropLink(graphtest.VendorFixture(), "www.colgate.edu-dns_record-ip-cdn")
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

// cloudAliasFixture is a graph whose subject has one name on a cloud provider
// attributed only through registration (no provider edge written) and one name
// CNAME'd to a provider-operated domain with no stored final address.
func cloudAliasFixture() graphtest.VendorGraph {
	g := dropLink(graphtest.VendorFixture(), "www.colgate.edu-dns_record-ip-cdn")
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	rr := func(from, to string, t int) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-dns-" + to, FromID: from, ToID: to, Label: "dns_record",
			Type: "BasicDNSRelation", Content: map[string]any{"header": map[string]any{"rr_type": t}}})
	}

	// AWS reached only through the netblock's registration (no provider edge),
	// exactly as this ithaca.edu data was collected.
	add("org-amazon", "Organization", "org-amazon", map[string]any{"name": "amazon.com"})
	add("cr-amazon", "ContactRecord", "https://rdap.example/amazon", nil)
	add("nb-aws2", "Netblock", "54.231.0.0/16", map[string]any{"cidr": "54.231.0.0/16"})
	add("ipnet-aws2", "IPNetRecord", "54.231.0.0/16", map[string]any{"name": "AMAZON-AES"})
	add("ip-aws2", "IPAddress", "54.231.1.1", map[string]any{"address": "54.231.1.1"})
	add("s3site.colgate.edu", "FQDN", "s3site.colgate.edu", map[string]any{"name": "s3site.colgate.edu"})
	link("cr-amazon", "organization", "org-amazon")
	link("nb-aws2", "registration", "ipnet-aws2")
	link("ipnet-aws2", "registrant", "cr-amazon")
	link("nb-aws2", "contains", "ip-aws2")
	link("colgate.edu", "node", "s3site.colgate.edu")
	rr("s3site.colgate.edu", "ip-aws2", 1) // A record

	// Azure Front Door reached only through a CNAME to a provider domain; the
	// final address was never resolved.
	add("esports.colgate.edu", "FQDN", "esports.colgate.edu", map[string]any{"name": "esports.colgate.edu"})
	add("ic-xyz.azurefd.net", "FQDN", "ic-xyz.azurefd.net", map[string]any{"name": "ic-xyz.azurefd.net"})
	link("colgate.edu", "node", "esports.colgate.edu")
	rr("esports.colgate.edu", "ic-xyz.azurefd.net", 5) // CNAME

	return g
}

func TestFindCloudAliasAndRegistration(t *testing.T) {
	g := cloudAliasFixture()
	catalog := graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}

	r, err := FindCloud(context.Background(), g, catalog, g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]CloudProviderShare{}
	for _, p := range r.Providers {
		got[p.Provider] = p
	}
	// AWS, recognized from the registration-attributed "amazon.com" label with
	// no provider edge present.
	aws, ok := got["Amazon Web Services"]
	if !ok || aws.Names != 1 {
		t.Errorf("aws share = %+v (all: %+v)", aws, r.Providers)
	}
	if strings.Join(aws.Networks, ",") != "54.231.0.0/16" {
		t.Errorf("aws networks = %+v", aws.Networks)
	}
	// Azure, recognized from the CNAME to azurefd.net with no stored address.
	az, ok := got["Microsoft Azure"]
	if !ok || az.Names != 1 {
		t.Errorf("azure share = %+v (all: %+v)", az, r.Providers)
	}
	if len(az.Networks) != 0 {
		t.Errorf("azure should have no network (alias only): %+v", az.Networks)
	}
	if r.OnCloud != 2 {
		t.Errorf("on_cloud = %d, want 2 (names %d, resolving %d)", r.OnCloud, r.Names, r.Resolving)
	}

	text := r.Text()
	for _, want := range []string{"Amazon Web Services: 1 name", "Microsoft Azure: 1 name", "esports.colgate.edu"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

// TestFindCloudNone reports no provider when nothing resolves into a
// recognized range.
func TestFindCloudNone(t *testing.T) {
	// Drop the base fixture's Fastly-fronted www name so nothing the subject
	// controls resolves into a recognized provider.
	g := dropLink(graphtest.VendorFixture(), "www.colgate.edu-dns_record-ip-cdn")
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
