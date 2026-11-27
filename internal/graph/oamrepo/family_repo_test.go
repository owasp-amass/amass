// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// The family lens reads stored OAM assets: FQDN names, DNS record types,
// netblock CIDRs, network registrations and certificate subjects.
func TestOrganizationFamilyOnSQLite(t *testing.T) {
	checkOrganizationFamily(t, openSQLite(t, "family.db"))
}

func checkOrganizationFamily(t *testing.T, repo repository.Repository) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := mergeFixture{t: t, ctx: ctx, repo: repo}

	poly := f.asset(&oamorg.Organization{ID: "sunypoly:1", Name: "suny polytechnic institute"})
	arin := f.asset(&oamorg.Organization{ID: "sunypoly:2", Name: "suny polytechnic institute"})

	cert := f.asset(&oamcert.TLSCertificate{Version: "3", SerialNumber: "1", SubjectCommonName: "www.sunyit.edu",
		IssuerCommonName: "R11", NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"})
	crCert := f.asset(&contact.ContactRecord{DiscoveredAt: "cert"})
	f.edge(cert, crCert, "subject_contact", "TLSCertificate")
	f.edge(crCert, poly, "organization", "TLSCertificate")

	prefix := netip.MustParsePrefix("2001:db8::/32")
	nb := f.asset(&network.Netblock{CIDR: prefix, Type: "IPv6"})
	rec := f.asset(&oamreg.IPNetRecord{CIDR: prefix, Handle: "NET6-2001-DB8-1", Type: "IPv6",
		StartAddress: prefix.Addr(), EndAddress: prefix.Addr(), Name: "SUNYPOLY"})
	f.edge(nb, rec, "registration", "RDAP")
	crNet := f.asset(&contact.ContactRecord{DiscoveredAt: "https://rdap.arin.net/registry/entity/SUNYP-1"})
	f.edge(rec, crNet, "registrant", "RDAP")
	f.edge(crNet, arin, "organization", "RDAP")

	apex := f.asset(&oamdns.FQDN{Name: "sunyit.edu"})
	www := f.asset(&oamdns.FQDN{Name: "www.sunyit.edu"})
	f.edge(apex, www, "node", "DNS")
	f.edge(cert, www, "common_name", "TLSCertificate")
	for i := 0; i < 6; i++ {
		name := f.asset(&oamdns.FQDN{Name: fmt.Sprintf("h%d.sunyit.edu", i)})
		f.edge(apex, name, "node", "DNS")
		ip := f.asset(&network.IPAddress{Address: netip.MustParseAddr(fmt.Sprintf("2001:db8::%d", i+1)), Type: "IPv6"})
		e, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: name, ToEntity: ip,
			Relation: &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 28, Class: 1}}})
		if err != nil || e == nil {
			t.Fatal(err)
		}
		f.edge(nb, ip, "contains", "DNS")
	}

	adapter := Adapter{Repo: repo}
	root, err := adapter.GetAsset(ctx, apex.ID)
	if err != nil {
		t.Fatal(err)
	}

	r, err := lens.FindOrganizationFamily(ctx, adapter, root)
	if err != nil {
		t.Fatal(err)
	}
	if r.Main == nil || len(r.Members) != 2 {
		t.Fatalf("report:\n%s", lens.FormatFamilyReport(r))
	}
	for _, m := range r.Members {
		if m.Relation != lens.FamilySame {
			t.Errorf("%s is %s, want %s:\n%s", m.Organization.ID, m.Relation, lens.FamilySame, lens.FormatFamilyReport(r))
		}
	}
	if len(r.Networks) != 1 || !r.Networks[0].Dedicated || r.Networks[0].CIDR != "2001:db8::/32" {
		t.Errorf("networks = %+v", r.Networks)
	}
}
