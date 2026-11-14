// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// The services lens reads the fields the HTTP probe stores, as SQLite
// returns them: the port relation's number and protocol, the response
// headers and the certificate.
func TestServicesOnSQLite(t *testing.T) {
	checkServices(t, openSQLite(t, "services.db"))
}

func checkServices(t *testing.T, repo repository.Repository) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := mergeFixture{t: t, ctx: ctx, repo: repo}

	apex := f.asset(&oamdns.FQDN{Name: "example.edu"})
	www := f.asset(&oamdns.FQDN{Name: "www.example.edu"})
	f.edge(apex, www, "node", "DNS")
	svc := f.asset(&oamplat.Service{ID: "svc-1", Type: "web-service", Output: "<html>", OutputLen: 6,
		Attributes: map[string][]string{"Server": {"Apache/2.4.58"}}})
	if _, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: www, ToEntity: svc,
		Relation: &oamgen.PortRelation{Name: "port", PortNumber: 8443, Protocol: "TCP"}}); err != nil {
		t.Fatal(err)
	}
	cert := f.asset(&oamcert.TLSCertificate{Version: "3", SerialNumber: "9", SubjectCommonName: "www.example.edu",
		IssuerCommonName: "R11", NotBefore: "2025-01-01T00:00:00Z", NotAfter: "2026-01-01T00:00:00Z"})
	f.edge(svc, cert, "certificate", "HTTP-Probes")

	adapter := Adapter{Repo: repo}
	root, err := adapter.GetAsset(ctx, apex.ID)
	if err != nil {
		t.Fatal(err)
	}
	r, err := lens.FindServices(ctx, adapter, Catalog{}, root, lens.LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Services) != 1 {
		t.Fatalf("services = %+v", r.Services)
	}
	s := r.Services[0]
	if strings.Join(s.Ports, ",") != "8443/TCP" || strings.Join(s.Software, ",") != "server: Apache/2.4.58" ||
		len(s.Certificates) != 1 || s.Certificates[0].Subject != "www.example.edu" || !s.Certificates[0].Expired {
		t.Errorf("service = %+v\n%s", s, lens.FormatServicesReport(r))
	}
}
