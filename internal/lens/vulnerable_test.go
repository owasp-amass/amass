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

	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/vuln"
)

func TestFindVulnerable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerabilities.json")
	defer func(f func() string) { VulnDataPath = f }(VulnDataPath)
	VulnDataPath = func() string { return path }
	g := graphtest.ServicesFixture()
	root := g.Assets["colgate.edu"]

	// Without data, the lens says how to fetch it.
	r, err := FindVulnerable(context.Background(), g, postureCatalog(), root, LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Software) != 0 || !strings.Contains(r.Text(), "amass vuln-update") {
		t.Fatalf("without data:\n%s", r.Text())
	}

	d := &vuln.Data{UpdatedAt: time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC),
		Products: map[string]*vuln.ProductData{"cpe:2.3:a:f5:nginx": {CVEs: map[string]*vuln.CVE{
			"CVE-2021-23017": {ID: "CVE-2021-23017", Score: 7.7, Severity: "HIGH",
				Ranges: []vuln.Range{{StartIncl: "0.6.18", EndExcl: "1.20.1"}}},
			"CVE-2099-0001": {ID: "CVE-2099-0001", Score: 9.8, Severity: "CRITICAL",
				Ranges: []vuln.Range{{StartIncl: "1.21.0"}}},
			"CVE-2099-0002": {ID: "CVE-2099-0002", Score: 5.3, Severity: "MEDIUM",
				Ranges: []vuln.Range{{Version: "1.18.0"}}},
			// NVD names nginx for every version, with no version or range
			"CVE-2007-0001": {ID: "CVE-2007-0001", Score: 7.8, Severity: "HIGH", Ranges: []vuln.Range{{}}},
		}}},
		KEV: map[string]vuln.KEVEntry{"CVE-2099-0002": {Name: "Example exploited flaw", DateAdded: "2026-01-02"}}}
	if err := d.Save(path); err != nil {
		t.Fatal(err)
	}

	r, err = FindVulnerable(context.Background(), g, postureCatalog(), root, LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Software) != 1 {
		t.Fatalf("software %+v\n%s", r.Software, r.Text())
	}

	s := r.Software[0]
	if s.Product != "nginx" || s.Version != "1.18.0" || len(s.CVEs) != 2 || s.KEV != 1 ||
		s.CVEs[0].CVE != "CVE-2099-0002" || s.CVEs[1].CVE != "CVE-2021-23017" {
		t.Errorf("nginx 1.18.0: %+v", s)
	}

	text := r.Text()
	for _, want := range []string{"known exploited (CISA KEV since 2026-01-02)", "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
		"backport", "updated 2026-11-15"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "CVE-2099-0001") {
		t.Errorf("a CVE outside the version's range was reported:\n%s", text)
	}

	// a CVE listed for every version is named but not counted
	if len(r.AllVersions) != 1 || r.AllVersions[0].CVEs[0] != "CVE-2007-0001" ||
		!strings.Contains(text, "Not counted") || !strings.Contains(text, "nginx 1.18.0: CVE-2007-0001") {
		t.Errorf("the CVE listed for every version: %+v\n%s", r.AllVersions, text)
	}

	facts := strings.Join(r.Facts(), "\n")
	if !strings.Contains(facts, "kev CVE-2099-0002 nginx 1.18.0") || !strings.Contains(facts, "cve CVE-2021-23017") {
		t.Errorf("facts:\n%s", facts)
	}
}

// Every product the services lens can identify is in the vulnerability
// catalog, as checked or with the reason it cannot be.
func TestVulnerabilityCatalogCoversFingerprints(t *testing.T) {
	cat, err := vuln.LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range loadProductFingerprints().Fingerprints {
		if _, reason, ok := cat.ProductNamed(f.Product); !ok && reason == "" {
			t.Errorf("product %q is not in vulnerabilities.json", f.Product)
		}
	}
}

// When the server header names the distribution, its own data judges the
// CVEs: those it settled are not counted, those an update fixes are said
// so, and the rest still apply.
func TestFindVulnerableByDistribution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerabilities.json")
	defer func(f func() string) { VulnDataPath = f }(VulnDataPath)
	VulnDataPath = func() string { return path }

	g := graphtest.ServicesFixture()
	web := g.Assets["svc-web"]
	web.Content = map[string]any{"service_type": "web-service",
		"attributes": map[string]any{"Server": []any{"nginx/1.18.0 (Ubuntu)"}}}
	g.Assets["svc-web"] = web

	d := &vuln.Data{UpdatedAt: time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC),
		Products: map[string]*vuln.ProductData{"cpe:2.3:a:f5:nginx": {CVEs: map[string]*vuln.CVE{
			"CVE-2021-23017": {ID: "CVE-2021-23017", Score: 7.7, Severity: "HIGH",
				Ranges: []vuln.Range{{StartIncl: "0.6.18", EndExcl: "1.20.1"}}},
			"CVE-2099-0002": {ID: "CVE-2099-0002", Score: 5.3, Severity: "MEDIUM",
				Ranges: []vuln.Range{{Version: "1.18.0"}}},
			"CVE-2099-0003": {ID: "CVE-2099-0003", Score: 9.8, Severity: "CRITICAL",
				Ranges: []vuln.Range{{EndExcl: "1.30.0"}}},
		}}},
		KEV: map[string]vuln.KEVEntry{"CVE-2099-0002": {Name: "Example exploited flaw", DateAdded: "2026-01-02"}},
		Distros: map[string]*vuln.DistroData{vuln.FamilyUbuntu: {Packages: map[string]*vuln.DistroPackage{
			"nginx": {
				Releases: map[string][]string{"focal": {"1.18.0-0ubuntu1.4"}, "noble": {"1.24.0-2ubuntu7"}},
				CVEs: map[string][]vuln.DistroState{
					"CVE-2021-23017": {{Release: "focal", State: vuln.StateFixed, Fixed: "1.18.0-0ubuntu1.2"}},
					"CVE-2099-0002":  {{Release: "focal", State: vuln.StateNotAffected}},
					"CVE-2099-0003":  {{Release: "focal", State: vuln.StateOpen}},
				}}}}}}
	if err := d.Save(path); err != nil {
		t.Fatal(err)
	}

	r, err := FindVulnerable(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Software) != 1 {
		t.Fatalf("software %+v\n%s", r.Software, r.Text())
	}

	s := r.Software[0]
	if s.Distribution != "Ubuntu" || strings.Join(s.Releases, ",") != "focal" || len(s.CVEs) != 1 ||
		s.CVEs[0].CVE != "CVE-2099-0003" || len(s.Update) != 1 || s.Update[0].CVE != "CVE-2021-23017" ||
		len(s.Settled) != 1 || s.KEV != 0 {
		t.Errorf("nginx 1.18.0 on Ubuntu: %+v", s)
	}

	text := r.Text()
	for _, want := range []string{"nginx 1.18.0 (Ubuntu focal)", "by Ubuntu's data, 1 still apply, 1 fixed by an update",
		"Fixed by an Ubuntu update", "fixed in 1.18.0-0ubuntu1.2"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "known exploited (CISA") {
		t.Errorf("a CVE Ubuntu says does not affect it was reported as exploited:\n%s", text)
	}

	// a distribution whose own errata are not read is named, by version alone
	web.Content = map[string]any{"service_type": "web-service",
		"attributes": map[string]any{"Server": []any{"nginx/1.18.0 (Rocky Linux)"}}}
	g.Assets["svc-web"] = web
	if r, err = FindVulnerable(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"],
		LensLimits{}); err != nil {
		t.Fatal(err)
	}
	if len(r.Software) != 1 || len(r.Software[0].CVEs) != 3 ||
		!strings.Contains(r.Text(), "Rocky Linux backports fixes") {
		t.Errorf("Rocky Linux: %+v\n%s", r.Software, r.Text())
	}
}
