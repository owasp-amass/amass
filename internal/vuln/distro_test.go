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

// Debian's own examples and the cases a banner raises (deb-version(7)).
func TestCompareDebian(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0+b1", -1},
		{"1.0-1", "1.0-1ubuntu0.1", -1},
		{"9.6p1-3ubuntu13.16", "9.6p1-3ubuntu13.5", 1},
		{"8.9p1-3ubuntu0.10", "1:8.9p1-3ubuntu0.6", 1}, // a banner shows no epoch
		{"1:9.2p1-2+deb12u3", "2:9.2p1-2+deb12u1", -1},
		{"2.4.62-1~deb12u2", "2.4.62-1~deb12u1", 1},
		{"2.4.62-1~deb12u1", "2.4.62-1", -1},
		{"1.2.3a", "1.2.3", 1},
		{"1.10", "1.9", 1},
	} {
		if got := CompareDebian(tc.a, tc.b); got != tc.want {
			t.Errorf("%s vs %s = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := CompareDebian(tc.b, tc.a); got != -tc.want {
			t.Errorf("%s vs %s = %d, want %d", tc.b, tc.a, got, -tc.want)
		}
	}
}

func TestRedHatRelease(t *testing.T) {
	for _, tc := range []struct{ pkg, major, name, version string }{
		{"httpd-0:2.4.6-97.el7_9.1", "7", "httpd", "2.4.6"},
		{"httpd:2.4-8040020211008164252.522a0ee4", "8", "httpd", "stream:2.4"},
		{"mod_http2-0:2.0.26-4.el9_6.3", "9", "mod_http2", "2.0.26"},
		{"openssl-1:1.1.1k-12.el8_9", "8", "openssl", "1.1.1k"},
		{"httpd-main-2.4.71-0.1.hum1", "", "httpd-main", "2.4.71"},
	} {
		major, name, version := redHatRelease(tc.pkg)
		if major != tc.major || name != tc.name || version != tc.version {
			t.Errorf("%s gave %q %q %q", tc.pkg, major, name, version)
		}
	}
	for name, want := range map[string]bool{"httpd": true, "httpd:2.4/httpd": true, "httpd:2.4/mod_ssl": true,
		"httpd:2.4": true, "mod_http2": false, "jbcs-httpd24-httpd": false} {
		if redHatNames(name, "httpd") != want {
			t.Errorf("%s names httpd: %v", name, !want)
		}
	}
}

// distroSite serves fake Debian, Ubuntu and Red Hat security data.
type distroSite struct {
	mu    sync.Mutex
	asked []string
}

func (s *distroSite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.asked = append(s.asked, r.URL.Path+"?"+r.URL.RawQuery)
	s.mu.Unlock()

	switch {
	case r.URL.Path == "/debian/json":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"bash": map[string]any{"CVE-2014-6271": map[string]any{}},
			"apache2": map[string]any{
				"CVE-2021-40438": map[string]any{"releases": map[string]any{
					"bookworm": map[string]any{"status": "resolved", "fixed_version": "2.4.49-1",
						"repositories": map[string]any{"bookworm": "2.4.62-1~deb12u2"}},
					"trixie": map[string]any{"status": "resolved", "fixed_version": "2.4.49-1",
						"repositories": map[string]any{"trixie": "2.4.66-1"}}}},
				"CVE-2024-38475": map[string]any{"releases": map[string]any{
					"bookworm": map[string]any{"status": "resolved", "fixed_version": "2.4.62-1~deb12u1",
						"repositories": map[string]any{"bookworm": "2.4.62-1~deb12u2"}}}},
				"CVE-2099-0001": map[string]any{"releases": map[string]any{
					"bookworm": map[string]any{"status": "open",
						"repositories": map[string]any{"bookworm": "2.4.62-1~deb12u2"}}}},
				"CVE-2003-0001": map[string]any{"releases": map[string]any{
					"bookworm": map[string]any{"status": "resolved", "fixed_version": "0",
						"repositories": map[string]any{"bookworm": "2.4.62-1~deb12u2"}}}},
			},
		})
	case r.URL.Path == "/ubuntu/cves.json":
		if r.URL.Query().Get("package") != "openssh" {
			_, _ = fmt.Fprint(w, `{"cves":[],"total_results":0}`)
			return
		}

		type st = map[string]string
		all := []map[string]any{
			{"id": "CVE-2023-38408", "packages": []any{map[string]any{"name": "openssh", "statuses": []st{
				{"release_codename": "upstream", "status": "released", "description": "1:9.3p2-1"},
				{"release_codename": "jammy", "status": "released", "description": "1:8.9p1-3ubuntu0.3"},
				{"release_codename": "noble", "status": "not-affected", "description": "1:9.6p1-3ubuntu1"}}}}},
			{"id": "CVE-2099-0002", "packages": []any{map[string]any{"name": "openssh", "statuses": []st{
				{"release_codename": "jammy", "status": "needed", "description": ""},
				{"release_codename": "noble", "status": "DNE", "description": ""}}}}},
		}
		var offset int
		_, _ = fmt.Sscan(r.URL.Query().Get("offset"), &offset)
		page := all[min(offset, len(all)):min(offset+1, len(all))] // one a page, to test paging
		_ = json.NewEncoder(w).Encode(map[string]any{"cves": page, "total_results": len(all)})
	case r.URL.Path == "/redhat/cve.json":
		if r.URL.Query().Get("package") != "httpd" || r.URL.Query().Get("page") != "1" {
			_, _ = fmt.Fprint(w, `[]`)
			return
		}

		_, _ = fmt.Fprint(w, `[
			{"CVE":"CVE-2021-40438","advisories":["RHSA-2021:3816"],
			 "affected_packages":["httpd:2.4-8040020211008164252.522a0ee4","httpd-0:2.4.6-97.el7_9.1"]},
			{"CVE":"CVE-2099-0003","advisories":[],"affected_packages":[]},
			{"CVE":"CVE-2099-0004","advisories":["RHSA-2099:1"],"affected_packages":["httpd-0:2.4.62-1.el9_5.1"]}]`)
	case r.URL.Path == "/redhat/cve/CVE-2021-40438.json":
		_, _ = fmt.Fprint(w, `{"affected_release":[
			{"product_name":"Red Hat Enterprise Linux 8","advisory":"RHSA-2021:3816",
			 "package":"httpd:2.4-8040020211008164252.522a0ee4"},
			{"product_name":"Red Hat Enterprise Linux 7","advisory":"RHSA-2021:3856","package":"httpd-0:2.4.6-97.el7_9.1"},
			{"product_name":"JBoss Core Services for RHEL 8","advisory":"RHSA-2021:3746",
			 "package":"jbcs-httpd24-httpd-0:2.4.37-76.el8jbcs"}],
			"package_state":[{"product_name":"Red Hat Enterprise Linux 9","fix_state":"Not affected",
			 "package_name":"httpd"}]}`)
	case r.URL.Path == "/redhat/cve/CVE-2099-0003.json":
		_, _ = fmt.Fprint(w, `{"package_state":[
			{"product_name":"Red Hat Enterprise Linux 8","fix_state":"Affected","package_name":"httpd:2.4/httpd"},
			{"product_name":"Red Hat Enterprise Linux 9","fix_state":"Will not fix","package_name":"httpd"}]}`)
	default:
		http.NotFound(w, r)
	}
}

func distroCatalog(t *testing.T, base string) {
	t.Helper()

	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}

	saved := cat
	t.Cleanup(func() { LoadCatalog = func() (Catalog, error) { return saved, nil } })
	cat.NVDAPI, cat.KEVFeed = base+"/cves", base+"/kev.json"
	cat.Distributions = []Distribution{
		{Family: FamilyDebian, Name: "Debian", Data: base + "/debian/json"},
		{Family: FamilyUbuntu, Name: "Ubuntu", Data: base + "/ubuntu/cves.json"},
		{Family: FamilyRedHat, Name: "Red Hat Enterprise Linux", Data: base + "/redhat/cve/",
			List: base + "/redhat/cve.json"},
	}
	cat.Products = []Product{
		{Product: "Apache HTTP Server", CPE: []string{"cpe:2.3:a:apache:http_server"},
			Packages: map[string][]string{FamilyDebian: {"apache2"}, FamilyRedHat: {"httpd"}}},
		{Product: "OpenSSH", CPE: []string{"cpe:2.3:a:openbsd:openssh"},
			Packages: map[string][]string{FamilyUbuntu: {"openssh"}}},
	}
	LoadCatalog = func() (Catalog, error) { return cat, nil }

	waits := retryWaits
	t.Cleanup(func() { retryWaits = waits })
	retryWaits = []time.Duration{time.Millisecond}
}

// The distributions' records of the CVEs in the data are read, and judge
// each CVE for a server by its release and, when known, its package.
func TestDistroUpdateAndJudge(t *testing.T) {
	site := &distroSite{}
	srv := httptest.NewServer(site)
	defer srv.Close()
	distroCatalog(t, srv.URL)

	nvd := &fakeNVD{pageSize: 10, cves: map[string][]map[string]any{
		"cpe:2.3:a:apache:http_server": {
			nvdCVE("CVE-2021-40438", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "2.4.0", "2.4.49", 9.0),
			nvdCVE("CVE-2024-38475", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "2.4.0", "2.4.60", 9.1),
			nvdCVE("CVE-2099-0001", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "2.4.0", "2.4.99", 7.5),
			nvdCVE("CVE-2099-0003", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "2.4.0", "2.4.99", 7.5),
			nvdCVE("CVE-2003-0001", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "2.0", "2.4.99", 5.0),
		},
		"cpe:2.3:a:openbsd:openssh": {
			nvdCVE("CVE-2023-38408", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "5.5", "9.3p2", 9.8),
			nvdCVE("CVE-2099-0002", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "5.5", "9.9", 5.0),
		},
	}}
	mux := http.NewServeMux()
	mux.Handle("/cves", nvd)
	mux.Handle("/kev.json", nvd)
	mux.Handle("/", site)
	srv.Config.Handler = mux

	path := filepath.Join(t.TempDir(), "vulnerabilities.json")
	u := &Updater{Client: srv.Client(), Pause: time.Nanosecond}
	if _, err := u.Update(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	for _, s := range site.asked {
		if strings.Contains(s, "bash") {
			t.Errorf("a package outside the catalog was kept: %s", s)
		}
	}

	d, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Distros[FamilyUbuntu].Packages["openssh"].CVEs; len(got) != 2 {
		t.Fatalf("Ubuntu's pages were not all read: %+v", got)
	}

	judge := func(product string, s DistroServer, id string) DistroVerdict {
		return d.Judge(product, s, []string{id})[id]
	}

	// Debian, with no package revision: the upstream version decides
	deb := DistroServer{Family: FamilyDebian, Upstream: "2.4.62"}
	for id, want := range map[string]string{
		"CVE-2021-40438": VerdictFixed,       // fixed in 2.4.49, before 2.4.62
		"CVE-2024-38475": VerdictUpdate,      // fixed in a 2.4.62 package revision
		"CVE-2099-0001":  VerdictOpen,        // still open in bookworm
		"CVE-2003-0001":  VerdictNotAffected, // Debian's "0"
		"CVE-2099-0003":  VerdictUntracked,   // Debian has no record
	} {
		if got := judge("Apache HTTP Server", deb, id); got.Verdict != want ||
			strings.Join(got.Releases, ",") != "bookworm" {
			t.Errorf("Debian %s: %+v, want %s in bookworm", id, got, want)
		}
	}

	// Ubuntu, with the banner's package version
	ssh := DistroServer{Family: FamilyUbuntu, Upstream: "8.9p1", Package: "8.9p1-3ubuntu0.10"}
	if got := judge("OpenSSH", ssh, "CVE-2023-38408"); got.Verdict != VerdictFixed ||
		got.Releases[0] != "jammy" {
		t.Errorf("Ubuntu jammy, a newer package than the fix: %+v", got)
	}

	ssh.Package = "8.9p1-3ubuntu0.1"
	if got := judge("OpenSSH", ssh, "CVE-2023-38408"); got.Verdict != VerdictOpen {
		t.Errorf("Ubuntu jammy, an older package than the fix: %+v", got)
	}
	if got := judge("OpenSSH", ssh, "CVE-2099-0002"); got.Verdict != VerdictOpen {
		t.Errorf("Ubuntu needed: %+v", got)
	}

	// Red Hat: RHEL 8's httpd 2.4.37 is in the 2.4 module stream
	rhel := DistroServer{Family: FamilyRedHat, Upstream: "2.4.37"}
	// fixed in every release, so its record is not read: the fixing package
	// names the fix
	if got := judge("Apache HTTP Server", rhel, "CVE-2021-40438"); got.Verdict != VerdictUpdate ||
		!strings.HasPrefix(got.Fixed, "httpd:2.4-") || strings.Join(got.Releases, ",") != "8" {
		t.Errorf("RHEL 8 fixed by an update: %+v", got)
	}
	if got := judge("Apache HTTP Server", rhel, "CVE-2099-0003"); got.Verdict != VerdictOpen {
		t.Errorf("RHEL 8 affected: %+v", got)
	}
	// 2.4.62 is RHEL 9's, not in RHEL 8's 2.4 stream, where Red Hat does not
	// ship it; RHEL 9 is not affected by CVE-2021-40438 but has CVE-2099-0003
	if got := judge("Apache HTTP Server", DistroServer{Family: FamilyRedHat, Upstream: "2.4.62"},
		"CVE-2099-0003"); got.Verdict != VerdictOpen || strings.Join(got.Releases, ",") != "9" {
		t.Errorf("RHEL 9's version: %+v", got)
	}

	// a CVE read from Red Hat is not read again while its advisories stand
	site.mu.Lock()
	site.asked = nil
	site.mu.Unlock()
	if _, err := u.Update(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	for _, s := range site.asked {
		if strings.HasPrefix(s, "/redhat/cve/") {
			t.Errorf("Red Hat's record was read again: %s", s)
		}
	}
}

// A distribution that cannot be read keeps its previous data, and the
// rest is saved.
func TestDistroFailureKeepsPrevious(t *testing.T) {
	site := &distroSite{}
	mux := http.NewServeMux()
	nvd := &fakeNVD{pageSize: 10, cves: map[string][]map[string]any{
		"cpe:2.3:a:apache:http_server": {
			nvdCVE("CVE-2021-40438", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "2.4.0", "2.4.49", 9.0)},
		"cpe:2.3:a:openbsd:openssh": {
			nvdCVE("CVE-2023-38408", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "5.5", "9.3p2", 9.8)},
	}}
	mux.Handle("/cves", nvd)
	mux.Handle("/kev.json", nvd)
	down := false
	mux.HandleFunc("/debian/json", func(w http.ResponseWriter, r *http.Request) {
		if down {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		site.ServeHTTP(w, r)
	})
	mux.Handle("/", site)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	distroCatalog(t, srv.URL)

	path := filepath.Join(t.TempDir(), "vulnerabilities.json")
	u := &Updater{Client: srv.Client(), Pause: time.Nanosecond}
	if _, err := u.Update(context.Background(), path); err != nil {
		t.Fatal(err)
	}

	down = true
	if _, err := u.Update(context.Background(), path); err == nil || !strings.Contains(err.Error(), "Debian") {
		t.Fatalf("the Debian failure was not reported: %v", err)
	}

	d, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Distros[FamilyDebian] == nil || d.Distros[FamilyDebian].Packages["apache2"] == nil {
		t.Error("Debian's previous data was not kept")
	}
}
