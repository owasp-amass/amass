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

	// A refresh within two hours does not ask NVD again.
	f.queries = nil
	now = now.Add(time.Hour)
	if res, err = u.Update(context.Background(), path); err != nil || len(f.queries) != 0 || res.CVEs != 3 {
		t.Errorf("within two hours: %+v, %v, queries %v", res, err, f.queries)
	}

	// The next refresh asks only for what changed since.
	now = now.Add(23 * time.Hour)
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

// flaky refuses requests for some products: a number of times, or always.
type flaky struct {
	*fakeNVD
	mu     sync.Mutex
	status map[string]int
	times  map[string]int
	asked  map[string]int
}

func (f *flaky) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cpe := r.URL.Query().Get("virtualMatchString")

	f.mu.Lock()
	f.asked[cpe]++
	refuse := f.status[cpe] != 0 && (f.times[cpe] < 0 || f.asked[cpe] <= f.times[cpe])
	f.mu.Unlock()
	if refuse {
		http.Error(w, "refused", f.status[cpe])
		return
	}

	f.fakeNVD.ServeHTTP(w, r)
}

func flakyCatalog(t *testing.T, url string, cpes ...string) {
	t.Helper()

	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}

	saved := cat
	t.Cleanup(func() { LoadCatalog = func() (Catalog, error) { return saved, nil } })
	cat.NVDAPI, cat.KEVFeed = url+"/cves", url+"/kev.json"
	cat.Products = nil
	for _, c := range cpes {
		cat.Products = append(cat.Products, Product{Product: c, CPE: []string{c}, Source: "https://example.org"})
	}
	LoadCatalog = func() (Catalog, error) { return cat, nil }

	waits := retryWaits
	t.Cleanup(func() { retryWaits = waits })
	retryWaits = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
}

// A transient refusal or server error is asked again, and the product is
// fetched.
func TestUpdateRetriesTransientFailures(t *testing.T) {
	nginx := "cpe:2.3:a:f5:nginx"
	f := &flaky{fakeNVD: &fakeNVD{pageSize: 10, cves: map[string][]map[string]any{nginx: {
		nvdCVE("CVE-2021-0001", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "0.6.18", "1.20.1", 8.1)}}},
		status: map[string]int{nginx: http.StatusServiceUnavailable}, times: map[string]int{nginx: 2},
		asked: map[string]int{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	flakyCatalog(t, srv.URL, nginx)

	u := &Updater{Client: srv.Client(), Pause: time.Nanosecond}
	res, err := u.Update(context.Background(), filepath.Join(t.TempDir(), "vulnerabilities.json"))
	if err != nil || res.CVEs != 1 || f.asked[nginx] != 3 {
		t.Errorf("got %+v, %v after %d requests", res, err, f.asked[nginx])
	}
}

// A product that cannot be fetched keeps its previous data, the others are
// saved, and the next refresh, no sooner than NVD allows, asks again.
func TestUpdateSavesWhatWasFetched(t *testing.T) {
	nginx, openssl := "cpe:2.3:a:f5:nginx", "cpe:2.3:a:openssl:openssl"
	f := &flaky{fakeNVD: &fakeNVD{pageSize: 10, cves: map[string][]map[string]any{
		nginx:   {nvdCVE("CVE-2021-0001", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "0.6.18", "1.20.1", 8.1)},
		openssl: {nvdCVE("CVE-2021-0009", "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", "1.1.1", "1.1.1l", 7.5)},
	}}, status: map[string]int{openssl: http.StatusInternalServerError}, times: map[string]int{openssl: -1},
		asked: map[string]int{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	flakyCatalog(t, srv.URL, nginx, openssl)

	path := filepath.Join(t.TempDir(), "vulnerabilities.json")
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	u := &Updater{Client: srv.Client(), Now: func() time.Time { return now }, Pause: time.Nanosecond}
	res, err := u.Update(context.Background(), path)
	if err == nil || !strings.Contains(err.Error(), openssl) || res.Products != 1 {
		t.Fatalf("got %+v, %v", res, err)
	}
	if f.asked[openssl] != len(retryWaits)+1 {
		t.Errorf("openssl was asked %d times, want %d", f.asked[openssl], len(retryWaits)+1)
	}

	d, err := Load(path)
	if err != nil || d.Products[nginx] == nil || d.Products[openssl] != nil || len(d.KEV) != 1 {
		t.Fatalf("saved %+v, %v", d, err)
	}
	if _, status, _ := d.Check("cpe:2.3:a:openssl:openssl", "1.1.1k"); status == Checked {
		t.Error("openssl was reported as checked")
	}

	if Stale(path, 24*time.Hour, now.Add(time.Hour)) {
		t.Error("asked again within NVD's two hours")
	}
	if !Stale(path, 24*time.Hour, now.Add(MinRefresh)) {
		t.Error("the missing product is not asked again after two hours")
	}

	// once it can be fetched, the data is complete
	f.mu.Lock()
	f.status = nil
	f.mu.Unlock()
	now = now.Add(MinRefresh)
	if res, err := u.Update(context.Background(), path); err != nil || res.Products != 2 {
		t.Fatalf("got %+v, %v", res, err)
	}
	if Stale(path, 24*time.Hour, now.Add(MinRefresh)) {
		t.Error("complete data is stale before its maximum age")
	}
}

// A request that asking again will not fix, such as a bad request, is not
// repeated.
func TestUpdateDoesNotRetryBadRequests(t *testing.T) {
	nginx := "cpe:2.3:a:f5:nginx"
	f := &flaky{fakeNVD: &fakeNVD{pageSize: 10}, status: map[string]int{nginx: http.StatusBadRequest},
		times: map[string]int{nginx: -1}, asked: map[string]int{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	flakyCatalog(t, srv.URL, nginx)

	u := &Updater{Client: srv.Client(), Pause: time.Nanosecond}
	if _, err := u.Update(context.Background(), filepath.Join(t.TempDir(), "v.json")); err == nil ||
		f.asked[nginx] != 1 {
		t.Errorf("got %v after %d requests, want an error after 1", err, f.asked[nginx])
	}
}
