// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// The dangling DNS lens reads stored CNAME records and the expiry dates of
// domain registration records.
func TestDanglingDNSOnSQLite(t *testing.T) {
	checkDanglingDNS(t, openSQLite(t, "dangling.db"))
}

func checkDanglingDNS(t *testing.T, repo repository.Repository) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := mergeFixture{t: t, ctx: ctx, repo: repo}
	cname := func(from, to *dbt.Entity) {
		if _, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: from, ToEntity: to,
			Relation: &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 5, Class: 1}}}); err != nil {
			t.Fatal(err)
		}
	}

	org := f.asset(&oamorg.Organization{ID: "example:1", Name: "Example University"})
	apex := f.asset(&oamdns.FQDN{Name: "example.edu"})
	dr := f.asset(&oamreg.DomainRecord{Domain: "example.edu", Name: "example.edu", ID: "example.edu"})
	f.edge(apex, dr, "registration", "RDAP")
	cr := f.asset(&contact.ContactRecord{DiscoveredAt: "https://rdap.example/example.edu"})
	f.edge(dr, cr, "registrant_contact", "RDAP")
	f.edge(cr, org, "organization", "RDAP")

	// An alias to a deleted cloud resource, and one to a lapsed domain.
	shop := f.asset(&oamdns.FQDN{Name: "shop.example.edu"})
	f.edge(apex, shop, "node", "DNS")
	cname(shop, f.asset(&oamdns.FQDN{Name: "example-shop.azurewebsites.net"}))
	promo := f.asset(&oamdns.FQDN{Name: "promo.example.edu"})
	f.edge(apex, promo, "node", "DNS")
	cname(promo, f.asset(&oamdns.FQDN{Name: "www.lapsed-agency.example"}))
	lapsed := f.asset(&oamdns.FQDN{Name: "lapsed-agency.example"})
	ldr := f.asset(&oamreg.DomainRecord{Domain: "lapsed-agency.example", Name: "lapsed-agency.example",
		ID: "lapsed-agency.example", ExpirationDate: "2020-01-01T00:00:00Z"})
	f.edge(lapsed, ldr, "registration", "RDAP")

	adapter := Adapter{Repo: repo}
	root, err := adapter.GetAsset(ctx, apex.ID)
	if err != nil {
		t.Fatal(err)
	}
	r, err := lens.FindDanglingDNS(ctx, adapter, Catalog{}, root, lens.LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	kinds := map[string]string{}
	for _, x := range r.Findings {
		kinds[x.Name+" "+x.Kind] = x.Target
	}
	if kinds["shop.example.edu "+lens.DanglingClaimable] != "example-shop.azurewebsites.net" ||
		kinds["promo.example.edu "+lens.DanglingExpired] != "www.lapsed-agency.example" {
		t.Errorf("findings = %+v\n%s", r.Findings, lens.FormatDanglingReport(r))
	}
}
