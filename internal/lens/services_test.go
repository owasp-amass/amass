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

func TestFindServices(t *testing.T) {
	defer func(f func() time.Time) { serviceNow = f }(serviceNow)
	serviceNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }

	g := graphtest.ServicesFixture()
	r, err := FindServices(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["colgate.edu"],
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
		"ssh service on unusual port 2222/TCP", "expired certificate for www.colgate.edu",
		"self-issued certificate for portal.colgate.edu", "server: nginx/1.18.0", "stored products: nginx", "runs nginx 1.18.0", "Identified software: nginx 1.18.0 1"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

func TestFindServicesWithNone(t *testing.T) {
	g := graphtest.VendorFixture()
	r, err := FindServices(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["colgate.edu"],
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
			"Apache HTTP Server 2.4.58"},
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
