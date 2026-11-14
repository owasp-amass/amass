// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
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
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "family.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := mergeFixture{t: t, ctx: ctx, repo: repo}

	clarkson := f.asset(&oamorg.Organization{ID: "clarkson:1", Name: "clarkson university"})
	arin := f.asset(&oamorg.Organization{ID: "clarkson:2", Name: "clarkson university"})

	cert := f.asset(&oamcert.TLSCertificate{Version: "3", SerialNumber: "1", SubjectCommonName: "www.clarkson.edu",
		IssuerCommonName: "R11", NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"})
	crCert := f.asset(&contact.ContactRecord{DiscoveredAt: "cert"})
	f.edge(cert, crCert, "subject_contact", "TLSCertificate")
	f.edge(crCert, clarkson, "organization", "TLSCertificate")

	prefix := netip.MustParsePrefix("2605:6480::/32")
	nb := f.asset(&network.Netblock{CIDR: prefix, Type: "IPv6"})
	rec := f.asset(&oamreg.IPNetRecord{CIDR: prefix, Handle: "NET6-2605-6480-1", Type: "IPv6",
		StartAddress: prefix.Addr(), EndAddress: prefix.Addr(), Name: "CLARKSON"})
	f.edge(nb, rec, "registration", "RDAP")
	crNet := f.asset(&contact.ContactRecord{DiscoveredAt: "https://rdap.arin.net/registry/entity/CLARKS-22"})
	f.edge(rec, crNet, "registrant", "RDAP")
	f.edge(crNet, arin, "organization", "RDAP")

	apex := f.asset(&oamdns.FQDN{Name: "clarkson.edu"})
	www := f.asset(&oamdns.FQDN{Name: "www.clarkson.edu"})
	f.edge(apex, www, "node", "DNS")
	f.edge(cert, www, "common_name", "TLSCertificate")
	for i := 0; i < 6; i++ {
		name := f.asset(&oamdns.FQDN{Name: fmt.Sprintf("h%d.clarkson.edu", i)})
		f.edge(apex, name, "node", "DNS")
		ip := f.asset(&network.IPAddress{Address: netip.MustParseAddr(fmt.Sprintf("2605:6480::%d", i+1)), Type: "IPv6"})
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

	r, err := ai.FindOrganizationFamily(ctx, adapter, root)
	if err != nil {
		t.Fatal(err)
	}
	if r.Main == nil || len(r.Members) != 2 {
		t.Fatalf("report:\n%s", ai.FormatFamilyReport(r))
	}
	for _, m := range r.Members {
		if m.Relation != ai.FamilySame {
			t.Errorf("%s is %s, want %s:\n%s", m.Organization.ID, m.Relation, ai.FamilySame, ai.FormatFamilyReport(r))
		}
	}
	if len(r.Networks) != 1 || !r.Networks[0].Dedicated || r.Networks[0].CIDR != "2605:6480::/32" {
		t.Errorf("networks = %+v", r.Networks)
	}
}
