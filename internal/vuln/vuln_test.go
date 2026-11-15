// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.20.1", "1.20.1", 0},
		{"1.20.1", "1.20.2", -1},
		{"1.9", "1.10", -1},
		{"2.4.57", "2.4.6", 1},
		{"8.9p1", "9.3p2", -1},
		{"8.9p1", "8.9", 1},
		{"1.1.1k", "1.1.1", 1},
		{"1.1.1k", "1.1.1w", -1},
		{"2.0.0rc1", "2.0.0", -1},
		{"2.0.0-beta2", "2.0.0-beta10", -1},
		{"3.0", "3.0.0", 0},
		{"3.0", "3.0.1", -1},
	} {
		if got := CompareVersions(tc.a, tc.b); (got < 0) != (tc.want < 0) || (got > 0) != (tc.want > 0) {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestRangeCovers(t *testing.T) {
	r := Range{StartIncl: "0.6.18", EndExcl: "1.20.1"}
	for v, want := range map[string]bool{"0.6.18": true, "1.18.0": true, "1.20.1": false, "0.6.17": false} {
		if r.Covers(v) != want {
			t.Errorf("%+v covers %s = %v", r, v, !want)
		}
	}
	if !(Range{Version: "8.9p1"}).Covers("8.9p1") || (Range{Version: "8.9p1"}).Covers("8.9p2") {
		t.Error("an exact version range")
	}
	if !(Range{}).Covers("1.0") {
		t.Error("a range with no bounds covers every version")
	}
}

// fakeNVD answers CVE API queries from a list, by product, and counts them.
type fakeNVD struct {
	mu       sync.Mutex
	queries  []string
	pageSize int
	cves     map[string][]map[string]any
}

func nvdCVE(id, criteria, startIncl, endExcl string, score float64) map[string]any {
	return map[string]any{"cve": map[string]any{
		"id": id, "published": "2021-06-01T13:15:07.853",
		"metrics": map[string]any{"cvssMetricV31": []any{map[string]any{"type": "Primary",
			"cvssData": map[string]any{"baseScore": score, "baseSeverity": "HIGH"}}}},
		"configurations": []any{map[string]any{"nodes": []any{map[string]any{"cpeMatch": []any{
			map[string]any{"vulnerable": true, "criteria": criteria, "versionStartIncluding": startIncl,
				"versionEndExcluding": endExcl},
			map[string]any{"vulnerable": false, "criteria": "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*"},
		}}}}},
	}}
}

func (f *fakeNVD) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasSuffix(r.URL.Path, "/kev.json") {
		_ = json.NewEncoder(w).Encode(map[string]any{"vulnerabilities": []any{
			map[string]any{"cveID": "CVE-2021-0002", "vulnerabilityName": "Example exploited flaw",
				"dateAdded": "2022-01-10", "dueDate": "2022-07-10"}}})
		return
	}

	f.queries = append(f.queries, r.URL.RawQuery)
	cpe := r.URL.Query().Get("virtualMatchString")
	all := f.cves[cpe]
	if r.URL.Query().Get("lastModStartDate") != "" {
		all = all[len(all)-1:] // only the newest changed
	}

	start := 0
	_, _ = fmt.Sscan(r.URL.Query().Get("startIndex"), &start)
	end := min(start+f.pageSize, len(all))
	_ = json.NewEncoder(w).Encode(map[string]any{"totalResults": len(all), "vulnerabilities": all[start:end]})
}

func TestUpdateAndCheck(t *testing.T) {
	nginx := "cpe:2.3:a:f5:nginx"
	f := &fakeNVD{pageSize: 1, cves: map[string][]map[string]any{nginx: {
		nvdCVE("CVE-2021-0001", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "0.6.18", "1.20.1", 8.1),
		nvdCVE("CVE-2021-0002", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.0", "1.22.0", 5.3),
		nvdCVE("CVE-2021-0003", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.21.0", "1.21.5", 9.8),
	}}}
	srv := httptest.NewServer(f)
	defer srv.Close()

	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}

	saved := cat
	defer func() { LoadCatalog = func() (Catalog, error) { return saved, nil } }()
	cat.NVDAPI, cat.KEVFeed = srv.URL+"/cves", srv.URL+"/kev.json"
	cat.Products = []Product{{Product: "nginx", CPE: []string{nginx}, Source: "https://example.org"}}
	LoadCatalog = func() (Catalog, error) { return cat, nil }

	path := filepath.Join(t.TempDir(), "vulnerabilities.json")
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	u := &Updater{Client: srv.Client(), Now: func() time.Time { return now }, Pause: time.Nanosecond}
	res, err := u.Update(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if res.Full != 1 || res.CVEs != 3 || res.KEV != 1 || len(f.queries) != 3 {
		t.Fatalf("result %+v after %d queries", res, len(f.queries))
	}
	if Stale(path, 24*time.Hour, now) || !Stale(path, 24*time.Hour, now.Add(25*time.Hour)) {
		t.Error("staleness")
	}

	d, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	matches, status, _ := d.Check("nginx", "1.20.0")
	if status != Checked || len(matches) != 2 || matches[0].CVE != "CVE-2021-0002" || !matches[0].KEV ||
		matches[1].CVE != "CVE-2021-0001" {
		t.Fatalf("1.20.0: %s %+v", status, matches)
	}
	if m, _, _ := d.Check("nginx", "1.22.0"); len(m) != 0 {
		t.Errorf("1.22.0 matched %+v", m)
	}
	if _, status, _ := d.Check("nginx", ""); status != NoVersion {
		t.Errorf("no version: %s", status)
	}
	if _, status, _ := d.Check("Example Server", "1.0"); status != Unknown {
		t.Errorf("unknown product: %s", status)
	}

	// The next refresh asks only for what changed since.
	now = now.Add(24 * time.Hour)
	f.queries = nil
	if res, err = u.Update(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if res.Full != 0 || len(f.queries) != 1 || !strings.Contains(f.queries[0], "lastModStartDate") || res.CVEs != 3 {
		t.Errorf("incremental result %+v, queries %v", res, f.queries)
	}
}

// Every product the services lens identifies is checked or says why not.
func TestCatalogCoversNoDuplicates(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for _, p := range cat.Products {
		if seen[p.Product] {
			t.Errorf("%s is listed twice", p.Product)
		}

		seen[p.Product] = true
	}
	for _, u := range cat.Unchecked {
		if seen[u.Product] || u.Reason == "" {
			t.Errorf("unchecked %s is listed twice or gives no reason", u.Product)
		}

		seen[u.Product] = true
	}
}
