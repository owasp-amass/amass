// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/vuln"
)

func urlAsset(id, raw string) graph.Asset {
	return graph.Asset{ID: id, Type: "URL", Key: raw, Content: map[string]any{"url": raw}}
}

func TestIdentifyWebApplications(t *testing.T) {
	apps := identifyWebApplications([]graph.Asset{
		urlAsset("u1", "https://www.example.edu/wp-includes/js/comment-reply.min.js?ver=6.5.2"),
		urlAsset("u2", "https://www.example.edu/wp-includes/js/jquery/jquery.min.js?ver=3.4.1"),
		urlAsset("u3", "https://www.example.edu/wp-content/plugins/Contact-Form-7/includes/js/index.js?ver=5.9"),
		urlAsset("u4", "https://www.example.edu/wp-content/themes/astra/style.css?ver=4.6.1"),
		// The core version is read only from the files WordPress versions itself.
		urlAsset("u5", "https://www.example.edu/wp-includes/js/jquery/ui/core.min.js?ver=1.13.2"),
		// WordPress in a subdirectory.
		urlAsset("u6", "http://news.example.edu:8080/blog/wp-json/oembed/1.0/embed?url=x"),
		urlAsset("u7", "https://www.example.edu/about/"),
		{ID: "f1", Type: "FQDN", Key: "www.example.edu"},
	})

	if len(apps) != 2 {
		t.Fatalf("applications %+v", apps)
	}

	news, www := apps[0], apps[1]
	if news.Site != "http://news.example.edu:8080" || news.Product != "WordPress" || len(news.Identified) != 0 {
		t.Errorf("subdirectory site: %+v", news)
	}
	if www.Site != "https://www.example.edu" || www.URLs != 5 {
		t.Errorf("site and URL count: %+v", www)
	}

	var got []string
	for _, p := range www.Identified {
		got = append(got, p.Product+" "+p.Version)
	}
	if strings.Join(got, ", ") != "WordPress 6.5.2, jQuery 3.4.1" {
		t.Errorf("identified releases %v", got)
	}
	if www.String() != "WordPress 6.5.2" {
		t.Errorf("name %q", www.String())
	}

	want := []WebComponent{{Kind: "plugin", Name: "contact-form-7", AssetVersions: []string{"5.9"}},
		{Kind: "theme", Name: "astra", AssetVersions: []string{"4.6.1"}}}
	if len(www.Components) != len(want) {
		t.Fatalf("components %+v", www.Components)
	}
	for i, c := range want {
		g := www.Components[i]
		if g.Kind != c.Kind || g.Name != c.Name || strings.Join(g.AssetVersions, ",") != c.AssetVersions[0] {
			t.Errorf("component %d: %+v, want %+v", i, g, c)
		}
	}
}

func TestVulnerableWebApplications(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerabilities.json")
	defer func(f func() string) { VulnDataPath = f }(VulnDataPath)
	VulnDataPath = func() string { return path }

	g := graphtest.ServicesFixture()
	for id, raw := range map[string]string{
		"wp1": "https://www.owasp.org/wp-includes/js/wp-embed.min.js?ver=6.1",
		"wp2": "https://www.owasp.org/wp-includes/js/jquery/jquery.js?ver=3.4.1",
		"wp3": "https://www.owasp.org/wp-content/plugins/js_composer/assets/js.js?ver=6.0",
	} {
		g.Assets[id] = urlAsset(id, raw)
		g.Links = append(g.Links, graph.Relation{ID: id + "-domain", FromID: id, ToID: "www.owasp.org",
			Label: "domain", Type: "SimpleRelation"})
	}

	d := &vuln.Data{UpdatedAt: time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC), Products: map[string]*vuln.ProductData{
		"cpe:2.3:a:jquery:jquery": {CVEs: map[string]*vuln.CVE{"CVE-2020-11022": {ID: "CVE-2020-11022", Score: 6.1,
			Severity: "MEDIUM", Ranges: []vuln.Range{{StartIncl: "1.2", EndExcl: "3.5.0"}}}}},
		"cpe:2.3:a:wordpress:wordpress": {CVEs: map[string]*vuln.CVE{}},
	}}
	if err := d.Save(path); err != nil {
		t.Fatal(err)
	}

	services, err := FindServices(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(services.Applications) != 1 || !strings.Contains(services.Text(),
		"WordPress 6.1 on https://www.owasp.org") ||
		!strings.Contains(services.Text(), "plugin js_composer (asset ver 6.0)") {
		t.Fatalf("services report:\n%s", services.Text())
	}

	r, err := FindVulnerable(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	text := r.Text()
	for _, want := range []string{"jQuery 3.4.1 on https://www.owasp.org: 1 CVE(s)", "CVE-2020-11022",
		"WordPress add-ons on 1 endpoint(s): 1 found (plugin js_composer)", "No CVEs for: WordPress 6.1"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

// Every product a web application rule can identify is in the
// vulnerability catalog, as checked or with the reason it cannot be.
func TestVulnerabilityCatalogCoversWebApplications(t *testing.T) {
	cat, err := vuln.LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range loadWebApplicationRules().Applications {
		products := []string{a.Product}
		for _, v := range a.Versions {
			products = append(products, v.Product)
		}
		for _, p := range products {
			if _, reason, ok := cat.ProductNamed(p); !ok && reason == "" {
				t.Errorf("product %q is not in vulnerabilities.json", p)
			}
		}
	}
}

// The core release is read from any core script WordPress versions with its
// own release (wp-util, user-profile, password-strength-meter), and a
// bundled jQuery release is named as jQuery, never as WordPress's.
func TestWordPressCoreReleaseFromCoreScripts(t *testing.T) {
	apps := identifyWebApplications([]graph.Asset{
		urlAsset("u1", "https://board.example.edu/wp-includes/js/wp-util.min.js?ver=7.1.5"),
		urlAsset("u2", "https://board.example.edu/wp-admin/js/user-profile.min.js?ver=7.1.5"),
		urlAsset("u3", "https://board.example.edu/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"),
		urlAsset("u4", "https://board.example.edu/wp-includes/js/dist/hooks.min.js?ver=f0f188028580e8dc1255"),
	})

	if len(apps) != 1 {
		t.Fatalf("applications %+v", apps)
	}
	if got := apps[0].String(); got != "WordPress 7.1.5" {
		t.Errorf("name %q, want WordPress 7.1.5", got)
	}

	r := &WebReport{Applications: apps, Total: 4}
	text := r.Text()
	if !strings.Contains(text, "https://board.example.edu: WordPress 7.1.5 (WordPress Foundation); bundles jQuery 3.7.1") {
		t.Errorf("web lens line:\n%s", text)
	}
}
