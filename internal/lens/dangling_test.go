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

	for _, n := range []string{"shop.colgate.edu", "colgate.azurewebsites.net", "old.colgate.edu",
		"legacy.example-host.com", "l1.colgate.edu", "l2.colgate.edu", "promo.colgate.edu",
		"promo.lapsed-agency.com", "ok.colgate.edu", "ok.example-host.com",
		"selector1._domainkey.colgate.edu", "selector1-colgate-edu._domainkey.sel.onmicrosoft.com",
		"promo2.colgate.edu", "c.storage.googleapis.com"} {
		name(n)
	}
	for _, n := range []string{"shop", "old", "l1", "l2", "promo", "promo2", "ok"} {
		link("colgate.edu", "node", n+".colgate.edu")
	}
	record("shop.colgate.edu", "colgate.azurewebsites.net", 5)
	record("promo2.colgate.edu", "c.storage.googleapis.com", 5)
	record("old.colgate.edu", "legacy.example-host.com", 5)
	record("l1.colgate.edu", "l2.colgate.edu", 5)
	record("l2.colgate.edu", "l1.colgate.edu", 5)
	record("promo.colgate.edu", "promo.lapsed-agency.com", 5)
	ip("ip-promo", "203.0.113.9")
	record("promo.lapsed-agency.com", "ip-promo", 1)
	registered("lapsed-agency.com", "2026-01-15")
	record("ok.colgate.edu", "ok.example-host.com", 5)
	ip("ip-ok", "203.0.113.10")
	record("ok.example-host.com", "ip-ok", 1)

	// A DKIM selector (an underscored RFC 8552 name) CNAMEs to a key host with
	// no stored address; that is normal for a _domainkey record, not a dangling
	// takeover, so the lens must not report it.
	link("colgate.edu", "node", "selector1._domainkey.colgate.edu")
	record("selector1._domainkey.colgate.edu", "selector1-colgate-edu._domainkey.sel.onmicrosoft.com", 5)

	// The registry's name server domain expires in ten days.
	registered("ultradns.net", "2026-11-24")

	// www's address record was last seen long before the name was.
	www := g.Assets["www.colgate.edu"]
	www.LastSeen = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	g.Assets["www.colgate.edu"] = www
	for i, e := range g.Links {
		if e.FromID == "www.colgate.edu" && e.ToID == "ip-cdn" {
			g.Links[i].LastSeen = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
		}
	}

	return g
}

func TestFindDanglingDNS(t *testing.T) {
	defer func(f func() time.Time) { danglingNow = f }(danglingNow)
	danglingNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }

	g := danglingFixture()
	r, err := FindDanglingDNS(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]DanglingFinding{}
	for _, f := range r.Findings {
		got[f.Kind+" "+f.Name] = f
	}
	want := []string{
		DanglingClaimable + " shop.colgate.edu",
		DanglingClaimable + " promo2.colgate.edu",
		DanglingExpired + " promo.colgate.edu",
		DanglingExpiring + " colgate.edu",
		DanglingUnresolved + " old.colgate.edu",
		DanglingLoop + " l1.colgate.edu",
		DanglingStale + " www.colgate.edu",
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing %s in %+v", k, r.Findings)
		}
	}
	if f := got[DanglingClaimable+" shop.colgate.edu"]; f.Service != "Azure App Service" || f.Source == "" {
		t.Errorf("claimable finding = %+v", f)
	}
	if f := got[DanglingClaimable+" promo2.colgate.edu"]; !strings.Contains(f.Service, "Google Cloud Storage") ||
		f.Source == "" {
		t.Errorf("GCS claimable finding = %+v", f)
	}
	for _, f := range r.Findings {
		if f.Name == "ok.colgate.edu" {
			t.Errorf("an alias with a stored address was reported: %+v", f)
		}
		if f.Name == "selector1._domainkey.colgate.edu" {
			t.Errorf("an underscored (DKIM) name with no address was reported as dangling: %+v", f)
		}
	}
	if r.Findings[0].Kind != DanglingClaimable {
		t.Errorf("findings are not ordered by severity: %+v", r.Findings)
	}

	text := FormatDanglingReport(r)
	for _, w := range []string{"possible subdomain takeover", "colgate.azurewebsites.net",
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
