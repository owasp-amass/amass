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
