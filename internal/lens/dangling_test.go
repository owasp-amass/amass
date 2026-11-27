// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// danglingFixture adds to the vendor fixture one record of each kind the
// dangling DNS lens reports, and one alias that is fine.
func danglingFixture() graphtest.VendorGraph {
	g := graphtest.VendorFixture()
	name := func(n string) {
		g.Assets[n] = graph.Asset{ID: n, Type: "FQDN", Key: n, Content: map[string]any{"name": n}}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	record := func(from, to string, rr int) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-rr-" + to, FromID: from, ToID: to, Label: "dns_record",
			Type: "BasicDNSRelation", Content: map[string]any{"header": map[string]any{"rr_type": rr}}})
	}
	registered := func(domain, expires string) {
		name(domain)
		id := "dr-" + domain
		g.Assets[id] = graph.Asset{ID: id, Type: "DomainRecord", Key: domain,
			Content: map[string]any{"domain": domain, "expiration_date": expires}}
		link(domain, "registration", id)
	}
	ip := func(id, addr string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "IPAddress", Key: addr, Content: map[string]any{"address": addr}}
	}

	for _, n := range []string{"shop.owasp.org", "owasp.azurewebsites.net", "old.owasp.org",
		"legacy.example-host.com", "l1.owasp.org", "l2.owasp.org", "promo.owasp.org",
		"promo.lapsed-agency.com", "ok.owasp.org", "ok.example-host.com",
		"selector1._domainkey.owasp.org", "selector1-owasp-edu._domainkey.sel.onmicrosoft.com",
		"promo2.owasp.org", "c.storage.googleapis.com"} {
		name(n)
	}
	for _, n := range []string{"shop", "old", "l1", "l2", "promo", "promo2", "ok"} {
		link("owasp.org", "node", n+".owasp.org")
	}
	record("shop.owasp.org", "owasp.azurewebsites.net", 5)
	record("promo2.owasp.org", "c.storage.googleapis.com", 5)
	record("old.owasp.org", "legacy.example-host.com", 5)
	record("l1.owasp.org", "l2.owasp.org", 5)
	record("l2.owasp.org", "l1.owasp.org", 5)
	record("promo.owasp.org", "promo.lapsed-agency.com", 5)
	ip("ip-promo", "198.51.100.9")
	record("promo.lapsed-agency.com", "ip-promo", 1)
	registered("lapsed-agency.com", "2026-01-15")
	record("ok.owasp.org", "ok.example-host.com", 5)
	ip("ip-ok", "198.51.100.10")
	record("ok.example-host.com", "ip-ok", 1)

	// A DKIM selector (an underscored RFC 8552 name) CNAMEs to a key host with
	// no stored address; that is normal for a _domainkey record, not a dangling
	// takeover, so the lens must not report it.
	link("owasp.org", "node", "selector1._domainkey.owasp.org")
	record("selector1._domainkey.owasp.org", "selector1-owasp-edu._domainkey.sel.onmicrosoft.com", 5)

	// The registry's name server domain expires in ten days.
	registered("ultradns.net", "2026-11-24")

	// www's address record was last seen long before the name was.
	www := g.Assets["www.owasp.org"]
	www.LastSeen = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	g.Assets["www.owasp.org"] = www
	for i, e := range g.Links {
		if e.FromID == "www.owasp.org" && e.ToID == "ip-cdn" {
			g.Links[i].LastSeen = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
		}
	}

	// A CNAME to an S3 bucket host that resolves (so the no-stored-address check
	// is skipped) but whose stored bucket a probe found missing: a confirmed takeover the
	// pattern-only path would miss.
	name("cdn.owasp.org")
	name("owasp-assets.s3.amazonaws.com")
	link("owasp.org", "node", "cdn.owasp.org")
	record("cdn.owasp.org", "owasp-assets.s3.amazonaws.com", 5)
	ip("ip-bucket", "52.216.0.1")
	record("owasp-assets.s3.amazonaws.com", "ip-bucket", 1)
	g.Assets["sb-owasp-assets"] = graph.Asset{ID: "sb-owasp-assets", Type: "StorageBucket", Key: "s3:owasp-assets",
		Content: map[string]any{"unique_id": "s3:owasp-assets", "bucket_name": "owasp-assets", "provider": "Amazon Web Services",
			"service": "s3", "exists": false, "public": false}}
	g.Links = append(g.Links, graph.Relation{ID: "owasp-assets-bucket", FromID: "owasp-assets.s3.amazonaws.com",
		ToID: "sb-owasp-assets", Label: "bucket", Type: "SimpleRelation"})

	return g
}

func TestFindDanglingDNS(t *testing.T) {
	defer func(f func() time.Time) { danglingNow = f }(danglingNow)
	danglingNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }

	g := danglingFixture()
	r, err := FindDanglingDNS(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]DanglingFinding{}
	for _, f := range r.Findings {
		got[f.Kind+" "+f.Name] = f
	}
	want := []string{
		DanglingClaimable + " shop.owasp.org",
		DanglingClaimable + " promo2.owasp.org",
		DanglingClaimable + " cdn.owasp.org",
		DanglingExpired + " promo.owasp.org",
		DanglingExpiring + " owasp.org",
		DanglingUnresolved + " old.owasp.org",
		DanglingLoop + " l1.owasp.org",
		DanglingStale + " www.owasp.org",
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing %s in %+v", k, r.Findings)
		}
	}
	if f := got[DanglingClaimable+" shop.owasp.org"]; f.Service != "Azure App Service" || f.Source == "" {
		t.Errorf("claimable finding = %+v", f)
	}
	if f := got[DanglingClaimable+" promo2.owasp.org"]; !strings.Contains(f.Service, "Google Cloud Storage") ||
		f.Source == "" {
		t.Errorf("GCS claimable finding = %+v", f)
	}
	if f := got[DanglingClaimable+" cdn.owasp.org"]; !strings.Contains(f.Detail, "does not exist") ||
		f.Source == "" {
		t.Errorf("confirmed bucket-takeover finding = %+v", f)
	}
	for _, f := range r.Findings {
		if f.Name == "ok.owasp.org" {
			t.Errorf("an alias with a stored address was reported: %+v", f)
		}
		if f.Name == "selector1._domainkey.owasp.org" {
			t.Errorf("an underscored (DKIM) name with no address was reported as dangling: %+v", f)
		}
	}
	if r.Findings[0].Kind != DanglingClaimable {
		t.Errorf("findings are not ordered by severity: %+v", r.Findings)
	}

	text := FormatDanglingReport(r)
	for _, w := range []string{"possible subdomain takeover", "owasp.azurewebsites.net",
		"lapsed-agency.com, whose stored registration expired 2026-01-15", "expires 2026-11-24",
		"not a live lookup"} {
		if !strings.Contains(text, w) {
			t.Errorf("report lacks %q:\n%s", w, text)
		}
	}
}

func TestClaimableServicesCiteSources(t *testing.T) {
	for _, s := range loadDanglingRules().ClaimableServices {
		if !strings.HasPrefix(s.Source, "https://") {
			t.Errorf("%s cites no source", s.Service)
		}
	}
	if _, ok := claimable("bucket.s3-website-us-east-1.amazonaws.com"); !ok {
		t.Error("an S3 website endpoint is not claimable")
	}
	if _, ok := claimable("c.storage.googleapis.com"); !ok {
		t.Error("a Google Cloud Storage endpoint is not claimable")
	}
	if _, ok := claimable("d111111abcdef8.cloudfront.net"); ok {
		t.Error("CloudFront distribution names are assigned, not claimable")
	}
}
