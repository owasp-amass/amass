// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
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
		"self-issued certificate for portal.colgate.edu", "server: nginx/1.18.0", "products: nginx"} {
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
