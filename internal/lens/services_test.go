// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func TestFindServices(t *testing.T) {
	defer func(f func() time.Time) { serviceNow = f }(serviceNow)
	serviceNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }

	g := graphtest.ServicesFixture()
	r, err := FindServices(context.Background(), g,
		graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp.org"],
		LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Services) != 2 || r.Hosts != 3 {
		t.Fatalf("services %+v on %d hosts", r.Services, r.Hosts)
	}

	byID := map[string]ExposedService{}
	for _, s := range r.Services {
		byID[s.Service.ID] = s
	}

	web, ssh := byID["svc-web"], byID["svc-ssh"]
	if len(web.Endpoints) != 2 || strings.Join(web.Software, ",") != "server: nginx/1.18.0" ||
		strings.Join(web.Products, ",") != "nginx" || len(web.Certificates) != 1 || !web.Certificates[0].Expired {
		t.Errorf("web service = %+v", web)
	}
	if strings.Join(ssh.UnusualPorts, ",") != "2222/TCP" || len(ssh.Certificates) != 1 ||
		!ssh.Certificates[0].SelfIssued {
		t.Errorf("ssh service = %+v", ssh)
	}
	if r.ByType["web-service"] != 1 || r.ByPort["443/TCP"] != 1 {
		t.Errorf("by type %v, by port %v", r.ByType, r.ByPort)
	}

	text := FormatServicesReport(r)
	for _, want := range []string{"2 service(s) on 3 host(s)", "What stands out:",
		"ssh service on unusual port 2222/TCP", "expired certificate for www.owasp.org",
		"self-issued certificate for portal.owasp.org", "server: nginx/1.18.0", "stored products: nginx", "runs nginx 1.18.0", "Identified software: nginx 1.18.0 1"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

func TestFindServicesInventoriesAliasedBuckets(t *testing.T) {
	defer func(f func() time.Time) { serviceNow = f }(serviceNow)
	serviceNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }

	g := graphtest.ServicesFixture()
	// A footprint name aliased to an object-storage bucket host (a CNAME target,
	// not a footprint member) whose bucket the probe stored as a StorageBucket.
	g.Assets["media.owasp.org"] = graph.Asset{ID: "media.owasp.org", Type: "FQDN", Key: "media.owasp.org",
		Content: map[string]any{"name": "media.owasp.org"}}
	g.Assets["owasp-media.s3.amazonaws.com"] = graph.Asset{ID: "owasp-media.s3.amazonaws.com", Type: "FQDN",
		Key: "owasp-media.s3.amazonaws.com", Content: map[string]any{"name": "owasp-media.s3.amazonaws.com"}}
	g.Assets["sb-media"] = graph.Asset{ID: "sb-media", Type: "StorageBucket", Key: "s3:owasp-media",
		Content: map[string]any{"unique_id": "s3:owasp-media", "bucket_name": "owasp-media",
			"provider": "Amazon Web Services", "service": "s3", "exists": true, "public": true}}
	g.Links = append(g.Links,
		graph.Relation{ID: "owasp.org-node-media", FromID: "owasp.org", ToID: "media.owasp.org",
			Label: "node", Type: "SimpleRelation"},
		graph.Relation{ID: "media-cname-bucket", FromID: "media.owasp.org", ToID: "owasp-media.s3.amazonaws.com",
			Label: "dns_record", Type: "BasicDNSRelation", Content: map[string]any{"header": map[string]any{"rr_type": 5}}},
		graph.Relation{ID: "media-host-bucket", FromID: "owasp-media.s3.amazonaws.com", ToID: "sb-media",
			Label: "bucket", Type: "SimpleRelation"})

	r, err := FindServices(context.Background(), g,
		graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if len(r.Buckets) != 1 {
		t.Fatalf("aliased bucket was not inventoried: %+v", r.Buckets)
	}
	b := r.Buckets[0]
	if b.Name != "owasp-media" || b.Provider != "Amazon Web Services" || !b.Exists || !b.Public ||
		!slices.Equal(b.Hosts, []string{"owasp-media.s3.amazonaws.com"}) ||
		!slices.Equal(b.Via, []string{"media.owasp.org"}) {
		t.Errorf("bucket = %+v", b)
	}
	// A bucket is not a listening service: no Service is invented for it.
	for _, svc := range r.Services {
		if svc.ServiceType == "object-storage" {
			t.Errorf("bucket inventoried as a service: %+v", svc)
		}
	}
	if !strings.Contains(r.Text(), "Amazon Web Services bucket owasp-media (world-readable)") {
		t.Errorf("report:\n%s", r.Text())
	}
}

func TestFindServicesWithNone(t *testing.T) {
	g := graphtest.VendorFixture()
	r, err := FindServices(context.Background(), g,
		graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp.org"],
		LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Services) != 0 || !strings.Contains(FormatServicesReport(r), "No service is stored") {
		t.Errorf("report = %s", FormatServicesReport(r))
	}
}

func TestIdentifyProducts(t *testing.T) {
	svc := func(kind, output string, headers map[string]any) graph.Asset {
		return graph.Asset{ID: "s", Type: "Service", Content: map[string]any{"service_type": kind, "output": output,
			"attributes": headers}}
	}
	for _, c := range []struct {
		svc  graph.Asset
		want string
	}{
		{svc("web-service", "", map[string]any{"Server": []any{"nginx/1.24.0 (Ubuntu)"}}), "nginx 1.24.0"},
		{svc("web-service", "", map[string]any{"Server": []any{"nginx"}}), "nginx"},
		{svc("web-service", "", map[string]any{"Server": []any{"Apache/2.4.58 (Unix) OpenSSL/3.0.13"}}),
			"Apache HTTP Server 2.4.58,OpenSSL 3.0.13"},
		{svc("web-service", "", map[string]any{"Server": []any{"Microsoft-IIS/10.0"},
			"X-Powered-By": []any{"ASP.NET"}, "X-AspNet-Version": []any{"4.0.30319"}}),
			"Microsoft IIS 10.0,ASP.NET 4.0.30319"},
		{svc("web-service", "", map[string]any{"x-powered-by": []any{"PHP/8.2.12"}}), "PHP 8.2.12"},
		{svc("ssh", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n", nil), "OpenSSH 9.6p1"},
		{svc("smtp", "220 mx.example.com ESMTP Postfix\r\n", nil), "Postfix"},
		{svc("smtp", "220 mx.example.com ESMTP Exim 4.97 Sat, 14 Nov 2026 00:00:00 +0000", nil), "Exim 4.97"},
		{svc("smtp", "220 EX01.corp.example Microsoft ESMTP MAIL service ready at Sat, 14 Nov 2026", nil),
			"Microsoft Exchange Server"},
		{svc("ftp", "220 (vsFTPd 3.0.5)", nil), "vsftpd 3.0.5"},
		{svc("imap", "* OK [CAPABILITY IMAP4rev1 LITERAL+] Dovecot (Ubuntu) ready.", nil), "Dovecot"},
		{svc("pop3", "+OK Dovecot ready.", nil), "Dovecot"},
		// A banner fingerprint reads only its service types.
		{svc("web-service", "SSH-2.0-OpenSSH_9.6p1", nil), ""},
		{svc("web-service", "", map[string]any{"Server": []any{"cloudflare"}}), ""},
	} {
		var got []string
		for _, p := range identifyProducts(c.svc) {
			got = append(got, strings.TrimSpace(p.Product+" "+p.Version))
			if p.Evidence == "" || !strings.HasPrefix(p.Source, "https://") {
				t.Errorf("%s has no evidence or source: %+v", p.Product, p)
			}
		}
		if strings.Join(got, ",") != c.want {
			t.Errorf("identified %q, want %q", strings.Join(got, ","), c.want)
		}
	}
}

func TestProductFingerprintCatalog(t *testing.T) {
	bad := productFingerprints{Fingerprints: []productFingerprint{{Product: "x", Header: "server",
		Pattern: "^x$", Version: 1, Source: "https://example.com"}}}
	if err := bad.validate(); err == nil {
		t.Error("a version group outside the pattern was accepted")
	}
	if len(loadProductFingerprints().Fingerprints) == 0 {
		t.Error("the catalog is empty")
	}
}

// Certificate dates are stored without a time zone by the collectors, so
// expiry is judged on those too.
func TestCertificateOfDatesWithoutZone(t *testing.T) {
	defer func(f func() time.Time) { serviceNow = f }(serviceNow)
	serviceNow = func() time.Time { return time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC) }

	for _, tc := range []struct {
		notAfter        string
		expired, expiry bool
	}{
		{"2026-11-13T04:12:07", true, false},
		{"2026-12-07T20:19:48", false, true},
		{"2027-03-03T00:17:03", false, false},
		{"2026-11-13T04:12:07Z", true, false},
	} {
		cert := graph.Asset{ID: "c", Type: "TLSCertificate", Content: map[string]any{
			"subject_common_name": "example.com", "issuer_common_name": "CA", "not_after": tc.notAfter}}
		c := certificateOf(cert, 30)
		if c.Expired != tc.expired || c.ExpiresSoon != tc.expiry {
			t.Errorf("%s: expired %v expires soon %v, want %v %v", tc.notAfter, c.Expired, c.ExpiresSoon,
				tc.expired, tc.expiry)
		}
	}
}
