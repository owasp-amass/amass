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
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// The registered subject lenses read what the enumeration stores for a
// domain: its registration record and status, certificates, mail exchanger
// and TXT records, as SQLite returns them.
func TestPostureLensesOnSQLite(t *testing.T) {
	checkPostureLenses(t, openSQLite(t, "posture.db"))
}

func checkPostureLenses(t *testing.T, repo repository.Repository) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := mergeFixture{t: t, ctx: ctx, repo: repo}

	org := f.asset(&oamorg.Organization{ID: "example:1", Name: "Example University"})
	apex := f.asset(&oamdns.FQDN{Name: "example.edu"})
	dr := f.asset(&oamreg.DomainRecord{Domain: "example.edu", Name: "example.edu", ID: "example.edu",
		ExpirationDate: "2020-03-01T00:00:00Z", Status: []string{"active"}})
	f.edge(apex, dr, "registration", "RDAP")
	cr := f.asset(&contact.ContactRecord{DiscoveredAt: "https://rdap.example/example.edu"})
	f.edge(dr, cr, "registrant_contact", "RDAP")
	f.edge(cr, org, "organization", "RDAP")

	www := f.asset(&oamdns.FQDN{Name: "www.example.edu"})
	f.edge(apex, www, "node", "DNS")
	cert := f.asset(&oamcert.TLSCertificate{Version: "3", SerialNumber: "77", SubjectCommonName: "www.example.edu",
		IssuerCommonName: "Example CA", NotBefore: "2019-01-01T00:00:00Z", NotAfter: "2020-01-01T00:00:00Z",
		SignatureAlgorithm: "SHA1-RSA"})
	f.edge(cert, www, "common_name", "TLSCertificate")

	mx := f.asset(&oamdns.FQDN{Name: "mx.mailhost-example.com"})
	if _, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: apex, ToEntity: mx,
		Relation: &oamdns.PrefDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 15, Class: 1},
			Preference: 10}}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateEntityProperty(ctx, apex, &oamdns.DNSRecordProperty{PropertyName: "dns_record",
		Header: oamdns.RRHeader{RRType: 16, Class: 1}, Data: "v=spf1 mx +all"}); err != nil {
		t.Fatal(err)
	}

	adapter := Adapter{Repo: repo}
	root, err := adapter.GetAsset(ctx, apex.ID)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string][]string{
		lens.LensCertificates: {lens.CertExpired + " www.example.edu", lens.CertWeak + " www.example.edu"},
		lens.LensDomains:      {lens.DomainExpired + " example.edu", lens.DomainUnlocked + " example.edu"},
		lens.LensEmail:        {lens.EmailSPFPermissive + " example.edu", "mail by mailhost-example.com"},
		lens.LensCoverage:     {"names_without_address 2 of 2"},
	}
	for name, facts := range want {
		l, ok := lens.SubjectLensNamed(name)
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		r, err := l.Find(ctx, adapter, Catalog{}, root, lens.Options{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := strings.Join(r.Facts(), "\n")
		for _, w := range facts {
			if !strings.Contains(got, w) {
				t.Errorf("%s lacks %q:\n%s", name, w, r.Text())
			}
		}
	}

	// Every other registered lens runs on the stored data.
	for _, l := range lens.SubjectLenses() {
		if l.NeedsOther {
			continue
		}
		if _, err := l.Find(ctx, adapter, Catalog{}, root, lens.Options{}); err != nil {
			t.Errorf("%s: %v", l.Name, err)
		}
	}
}
