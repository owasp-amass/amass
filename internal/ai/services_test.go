// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// servicesFixture adds what the HTTP and SSH probes store to the vendor
// fixture: a web service on www.colgate.edu with a server header, an
// expired certificate and a product, and an SSH service on an unusual port
// of portal.colgate.edu presenting a self-issued certificate.
func servicesFixture() vendorGraph {
	g := vendorFixture()
	add := func(id, typ string, content map[string]any) {
		g.assets[id] = Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	port := func(from, to string, n int) {
		g.links = append(g.links, Relation{ID: from + "-port-" + to, FromID: from, ToID: to, Label: "port",
			Type: "PortRelation", Content: map[string]any{"port_number": n, "protocol": "TCP"}})
	}
	link := func(from, label, to string) {
		g.links = append(g.links, Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: "SimpleRelation"})
	}

	add("svc-web", "Service", map[string]any{"unique_id": "svc-web", "service_type": "web-service",
		"attributes": map[string]any{"Server": []any{"nginx/1.18.0"}, "Content-Type": []any{"text/html"}}})
	add("svc-ssh", "Service", map[string]any{"unique_id": "svc-ssh", "service_type": "ssh"})
	add("cert-web", "TLSCertificate", map[string]any{"subject_common_name": "www.colgate.edu",
		"issuer_common_name": "R11", "not_after": "2026-01-01T00:00:00Z"})
	add("cert-ssh", "TLSCertificate", map[string]any{"subject_common_name": "portal.colgate.edu",
		"issuer_common_name": "portal.colgate.edu", "not_after": "2030-01-01T00:00:00Z"})
	add("nginx", "Product", map[string]any{"name": "nginx"})

	port("www.colgate.edu", "svc-web", 443)
	port("colgate.edu", "svc-web", 443)
	port("portal.colgate.edu", "svc-ssh", 2222)
	link("svc-web", "certificate", "cert-web")
	link("svc-ssh", "certificate", "cert-ssh")
	link("svc-web", "product_used", "nginx")

	return g
}

func TestFindServices(t *testing.T) {
	defer func(f func() time.Time) { serviceNow = f }(serviceNow)
	serviceNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }

	g := servicesFixture()
	r, err := FindServices(context.Background(), g, vendorCatalog{testOAMCatalog}, g.assets["colgate.edu"],
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
	g := vendorFixture()
	r, err := FindServices(context.Background(), g, vendorCatalog{testOAMCatalog}, g.assets["colgate.edu"],
		LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Services) != 0 || !strings.Contains(FormatServicesReport(r), "No service is stored") {
		t.Errorf("report = %s", FormatServicesReport(r))
	}
}

func TestIdentifyProducts(t *testing.T) {
	svc := func(kind, output string, headers map[string]any) Asset {
		return Asset{ID: "s", Type: "Service", Content: map[string]any{"service_type": kind, "output": output,
			"attributes": headers}}
	}
	for _, c := range []struct {
		svc  Asset
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

// A question about exposed services is planned as the services answer and
// answered by the lens, with the identified software in the answer.
func TestAskServices(t *testing.T) {
	g := servicesFixture()
	reply := `{"subject":{"type":"FQDN","field":"name","value":"colgate.edu"},"target_types":[],` +
		`"direction":"both","purpose":"connected","relationships":[],"path_rule":"","answer":"services","columns":[]}`
	model := &plannerModel{replies: []string{reply}}
	agent := Agent{Model: model, Runner: ToolRunner{Graph: g, Catalog: vendorCatalog{testOAMCatalog},
		Limits: DefaultLimits()}}

	res, err := agent.AskAdaptive(context.Background(), "What services does colgate.edu expose?", AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ServicesReport == nil || model.calls != 1 || !strings.Contains(res.Answer, "runs nginx 1.18.0") {
		t.Fatalf("calls %d, answer:\n%s", model.calls, res.Answer)
	}

	raw, err := json.Marshal(goalJSONSchema(testOAMCatalog.Relations(), nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{LensServices, LensGroupVendors} {
		if !strings.Contains(string(raw), `"`+kind+`"`) {
			t.Errorf("the goal schema does not offer the %s answer", kind)
		}
	}
}
