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

func TestFindExposure(t *testing.T) {
	defer func(f func() time.Time) { serviceNow = f }(serviceNow)
	serviceNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }

	g := graphtest.ServicesFixture()
	g.Assets["svc-rdp"] = graph.Asset{ID: "svc-rdp", Type: "Service", Key: "svc-rdp",
		Content: map[string]any{"unique_id": "svc-rdp", "service_type": "unknown"}}
	g.Links = append(g.Links, graph.Relation{ID: "portal-rdp", FromID: "portal.colgate.edu", ToID: "svc-rdp",
		Label: "port", Type: "PortRelation", Content: map[string]any{"port_number": 3389, "protocol": "TCP"}})
	url := "https://portal.colgate.edu/wp-admin/"
	g.Assets[url] = graph.Asset{ID: url, Type: "URL", Key: url, Content: map[string]any{"url": url}}
	g.Links = append(g.Links, graph.Relation{ID: "url-domain", FromID: url, ToID: "portal.colgate.edu",
		Label: "domain", Type: "SimpleRelation"})

	r, err := FindExposure(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	classes := map[string]ExposureClass{}
	for _, c := range r.Classes {
		classes[c.Name] = c
	}
	if c := classes["remote_access"]; c.Count != 2 {
		t.Errorf("remote access = %+v (want the SSH and RDP services)", c)
	}
	if c := classes["login_pages"]; c.Count != 1 || c.Examples[0] != url {
		t.Errorf("login pages = %+v", c)
	}
	if classes[ExposureUnusualPort].Count != 1 || classes[ExposureBadCert].Count != 2 {
		t.Errorf("classes = %+v", r.Classes)
	}
	if !strings.Contains(r.Text(), "Remote access and shells (2)") {
		t.Errorf("report:\n%s", r.Text())
	}
}

func TestConcentrationLevels(t *testing.T) {
	cases := []struct {
		groups []ChangeGroup
		want   string
	}{
		{[]ChangeGroup{{Key: "Cloudflare", Count: 3}}, ConcentrationSingle},
		{[]ChangeGroup{{Key: "Cloudflare", Count: 4}, {Key: "NS1", Count: 1}}, ConcentrationDominant},
		{[]ChangeGroup{{Key: "Cloudflare", Count: 2}, {Key: "NS1", Count: 2}}, ConcentrationDiverse},
		{[]ChangeGroup{{Key: "own name servers", Count: 5}}, ConcentrationOwn},
		{[]ChangeGroup{{Key: "own name servers", Count: 5}, {Key: "NS1", Count: 1}}, ConcentrationFew},
		{[]ChangeGroup{{Key: "own name servers", Count: 1}, {Key: "NS1", Count: 4}}, ConcentrationSingle},
	}
	for _, c := range cases {
		got, ok := concentrationOf("DNS providers", "domain(s)", c.groups)
		if !ok || got.Level != c.want {
			t.Errorf("%+v: level %q, want %q", c.groups, got.Level, c.want)
		}
	}
	if _, ok := concentrationOf("DNS providers", "domain(s)", nil); ok {
		t.Error("an empty category was reported")
	}
}

func TestFindConcentration(t *testing.T) {
	g := postureFixture()
	r, err := FindConcentration(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	cats := map[string]Concentration{}
	for _, c := range r.Categories {
		cats[c.Category] = c
	}
	for _, name := range []string{"DNS providers", "registrars", "certificate authorities", "hosting", "mail providers"} {
		if _, ok := cats[name]; !ok {
			t.Errorf("missing %s in %+v", name, r.Categories)
		}
	}
	if c := cats["certificate authorities"]; c.Level != ConcentrationDiverse || c.Total != 3 {
		t.Errorf("certificate authorities = %+v", c)
	}
}

func TestFindCoverage(t *testing.T) {
	g := postureFixture()
	root := g.Assets["colgate.edu"]
	root.LastSeen = time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	g.Assets["colgate.edu"] = root
	ns := g.Assets["ns1.colgate.edu"]
	ns.LastSeen = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	g.Assets["ns1.colgate.edu"] = ns

	r, err := FindCoverage(context.Background(), g, postureCatalog(), root, LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	gaps := map[string]CoverageGap{}
	for _, gp := range r.Gaps {
		gaps[gp.Name] = gp
	}
	if gp := gaps["names_without_address"]; gp.Missing != 2 || gp.Of != 4 {
		t.Errorf("names without address = %+v", gp)
	}
	if gp := gaps["domains_without_registration"]; gp.Missing != 0 || gp.Of != 1 {
		t.Errorf("domains without registration = %+v", gp)
	}
	if r.ByType["FQDN"] != 4 || !strings.Contains(r.Text(), "names without address: 2 of 4 (50%)") {
		t.Errorf("report:\n%s", r.Text())
	}
}

func TestFindGeography(t *testing.T) {
	g := postureFixture()
	g.Assets["loc"] = graph.Asset{ID: "loc", Type: "Location", Key: "13 Oak Dr",
		Content: map[string]any{"address": "13 Oak Dr", "city": "Hamilton", "country": "us"}}
	g.Links = append(g.Links, graph.Relation{ID: "colgate-loc", FromID: "colgate", ToID: "loc", Label: "location",
		Type: "SimpleRelation"})

	r, err := FindGeography(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Own) != 1 || r.Own[0].Key != "US" || !strings.Contains(r.Own[0].Examples[0], "Hamilton") {
		t.Errorf("own = %+v", r.Own)
	}
	hosted := map[string]int{}
	for _, h := range r.Hosting {
		hosted[h.Key] = h.Count
	}
	if hosted["its own networks"] != 1 {
		t.Errorf("hosting = %+v", r.Hosting)
	}
}

func TestFindShared(t *testing.T) {
	g := postureFixture()
	// Hamilton's registration uses the same DNS provider.
	g.Links = append(g.Links, graph.Relation{ID: "drh-ns", FromID: "dr-hamilton", ToID: "pdns1.ultradns.net",
		Label: "name_server", Type: "SimpleRelation"})

	r, err := FindShared(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"],
		g.Assets["hamilton.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	shared := false
	for _, v := range r.SharedVendors {
		shared = shared || strings.Contains(strings.ToLower(v.Key), "ultradns")
	}
	if !shared || r.OnlyA == 0 || r.OnlyB == 0 {
		t.Errorf("compare = %+v", r)
	}
	if !strings.Contains(r.Text(), "Outside parties both depend on") {
		t.Errorf("report:\n%s", r.Text())
	}

	if _, err := FindShared(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"],
		g.Assets["colgate.edu"], LensLimits{}); err == nil {
		t.Error("a subject was compared with itself")
	}
}
