// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

func orgCount(t *testing.T, sess *plugintest.Session) int {
	t.Helper()
	ents, err := sess.DB().FindEntitiesByType(context.Background(), oam.Organization, time.Now().Add(-time.Hour), 100)
	if err != nil {
		return 0
	}
	return len(ents)
}

func linked(t *testing.T, sess *plugintest.Session, from *dbt.Entity, label string, to *dbt.Entity) bool {
	t.Helper()
	edges, err := sess.DB().OutgoingEdges(context.Background(), from, time.Time{}, label)
	if err != nil {
		return false
	}
	for _, e := range edges {
		if e.ToEntity.ID == to.ID {
			return true
		}
	}
	return false
}

func TestCreateOrgAssetNewOrganization(t *testing.T) {
	sess := plugintest.NewSession(t)
	cr := sess.Asset(t, &oamcon.ContactRecord{DiscoveredAt: "https://rdap.example/acme"})

	orgent, err := CreateOrgAsset(sess, cr, &oamgen.SimpleRelation{Name: "organization"},
		&oamorg.Organization{Name: "Acme, Inc.", Jurisdiction: "United States"}, srcA)
	if err != nil {
		t.Fatal(err)
	}
	o := orgent.Asset.(*oamorg.Organization)
	// the record carries the normalized name; the name as written is a claim
	if o.Name != "acme" || o.Jurisdiction != "US" {
		t.Errorf("organization = %+v; want the normalized name and the country code", o)
	}
	if got, err := FindOrgByNameClaim(sess, "Acme, Inc.", srcA); err != nil || got.ID != orgent.ID {
		t.Errorf("the name claim = %v, %v", got, err)
	}
	if !linked(t, sess, cr, "organization", orgent) {
		t.Error("the contact record is not linked to the organization")
	}
	tags, _ := sess.DB().FindEntityTags(context.Background(), orgent, time.Time{}, "jurisdiction")
	if len(tags) != 1 {
		t.Errorf("jurisdiction claims = %d", len(tags))
	}
}

func TestCreateOrgAssetReuses(t *testing.T) {
	t.Run("same source and name", func(t *testing.T) {
		sess := plugintest.NewSession(t)
		a, err := CreateOrgAsset(sess, nil, nil, &oamorg.Organization{Name: "Acme Corp"}, srcA)
		if err != nil {
			t.Fatal(err)
		}
		b, err := CreateOrgAsset(sess, nil, nil, &oamorg.Organization{Name: "Acme Corp"}, srcA)
		if err != nil || b.ID != a.ID || orgCount(t, sess) != 1 {
			t.Errorf("second record = %v, %v; %d organizations", b, err, orgCount(t, sess))
		}
	})
	t.Run("same source and legal name", func(t *testing.T) {
		sess := plugintest.NewSession(t)
		a, _ := CreateOrgAsset(sess, nil, nil, &oamorg.Organization{Name: "Acme", LegalName: "Acme Corporation"}, srcA)
		b, err := CreateOrgAsset(sess, nil, nil,
			&oamorg.Organization{Name: "Acme Holdings", LegalName: "Acme Corporation"}, srcA)
		if err != nil || b.ID != a.ID {
			t.Errorf("second record = %v, %v; want the first", b, err)
		}
	})
	t.Run("registration number in a compatible jurisdiction", func(t *testing.T) {
		sess := plugintest.NewSession(t)
		a, _ := CreateOrgAsset(sess, nil, nil, &oamorg.Organization{Name: "Acme Corp", Jurisdiction: "US-DE",
			RegistrationID: "5551234"}, srcA)
		b, err := CreateOrgAsset(sess, nil, nil, &oamorg.Organization{Name: "ACME CORPORATION", Jurisdiction: "US",
			RegistrationID: "5551234"}, srcB)
		if err != nil || b.ID != a.ID {
			t.Errorf("another source's record of the same registration = %v, %v; want the first", b, err)
		}
	})
	t.Run("normalized name in a compatible jurisdiction", func(t *testing.T) {
		sess := plugintest.NewSession(t)
		a, _ := CreateOrgAsset(sess, nil, nil, &oamorg.Organization{Name: "Acme, LLC", Jurisdiction: "US-DE"}, srcA)
		b, err := CreateOrgAsset(sess, nil, nil, &oamorg.Organization{Name: "Acme Inc", Jurisdiction: "US"}, srcB)
		if err != nil || b.ID != a.ID {
			t.Errorf("same brand, compatible jurisdiction = %v, %v; want the first", b, err)
		}
		c, err := CreateOrgAsset(sess, nil, nil, &oamorg.Organization{Name: "Acme Ltd", Jurisdiction: "GB"}, srcB)
		if err != nil || c.ID == a.ID {
			t.Errorf("same brand in another country = %v, %v; want a new organization", c, err)
		}
	})
	t.Run("named on the same contact record", func(t *testing.T) {
		sess := plugintest.NewSession(t)
		cr := sess.Asset(t, &oamcon.ContactRecord{DiscoveredAt: "https://rdap.example/acme"})
		rel := &oamgen.SimpleRelation{Name: "organization"}
		a, _ := CreateOrgAsset(sess, cr, rel, &oamorg.Organization{Name: "Acme Corp"}, srcA)
		b, err := CreateOrgAsset(sess, cr, rel, &oamorg.Organization{Name: "ACME CORP"}, srcB)
		if err != nil || b.ID != a.ID {
			t.Errorf("another source naming the record's organization = %v, %v; want the first", b, err)
		}
	})
	t.Run("sharing a street address", func(t *testing.T) {
		sess := plugintest.NewSession(t)
		addr := &oamcon.StreetAddress{Address: "1 Main St, Springfield, IL", BuildingNumber: "1",
			StreetName: "Main St", City: "Springfield", Province: "IL", Country: "US"}
		loc := sess.Asset(t, addr)
		cr1 := sess.Asset(t, &oamcon.ContactRecord{DiscoveredAt: "https://rdap.example/1"})
		sess.Edge(t, cr1, &oamgen.SimpleRelation{Name: "street_address"}, loc)
		rel := &oamgen.SimpleRelation{Name: "organization"}
		a, _ := CreateOrgAsset(sess, cr1, rel, &oamorg.Organization{Name: "Acme Corp"}, srcA)

		cr2 := sess.Asset(t, &oamcon.ContactRecord{DiscoveredAt: "https://rdap.example/2"})
		sess.Edge(t, cr2, &oamgen.SimpleRelation{Name: "street_address"}, loc)
		b, err := CreateOrgAsset(sess, cr2, rel, &oamorg.Organization{Name: "Acme Corp."}, srcB)
		if err != nil || b.ID != a.ID {
			t.Errorf("a record at the same address = %v, %v; want the first", b, err)
		}
		if !linked(t, sess, cr2, "organization", a) {
			t.Error("the second contact record is not linked to the organization")
		}
	})
}

// Different organizations stay separate.
func TestCreateOrgAssetKeepsDifferentOrganizationsApart(t *testing.T) {
	sess := plugintest.NewSession(t)
	a, _ := CreateOrgAsset(sess, nil, nil, &oamorg.Organization{Name: "Acme Corp"}, srcA)
	b, err := CreateOrgAsset(sess, nil, nil, &oamorg.Organization{Name: "Globex Corp"}, srcA)
	if err != nil || b.ID == a.ID || orgCount(t, sess) != 2 {
		t.Errorf("a different name = %v, %v; %d organizations", b, err, orgCount(t, sess))
	}
	if _, err := CreateOrgAsset(sess, nil, nil, &oamorg.Organization{}, srcA); err == nil {
		t.Error("an organization without a name was created")
	}
	if _, err := CreateOrgAsset(sess, nil, nil, &oamorg.Organization{Name: "Acme"}, nil); err == nil {
		t.Error("an organization without a source was created")
	}
}

func TestNameMatch(t *testing.T) {
	sess := plugintest.NewSession(t)
	orgent := newOrg(t, sess, "acme:1", "acme corporation")
	if _, err := CreateOrgNameClaim(sess, orgent, "Acme Corporation", srcA); err != nil {
		t.Fatal(err)
	}

	exact, partial, found := NameMatch(sess, orgent, []string{"ACME CORP", "Acmee Corporation", "Globex"})
	if !found || !slices.Equal(exact, []string{"ACME CORP"}) || !slices.Equal(partial, []string{"Acmee Corporation"}) {
		t.Errorf("exact = %v, partial = %v, found %v", exact, partial, found)
	}
	// a name that only contains the organization's is a different one
	for _, other := range []string{"Globex Industries", "Acme Hospitality REIT", "Acme Holdings"} {
		if _, _, found := NameMatch(sess, orgent, []string{other}); found {
			t.Errorf("%q matched", other)
		}
	}
	if _, _, found := NameMatch(sess, nil, []string{"acme"}); found {
		t.Error("a nil organization matched")
	}
}

func TestOrgsSharing(t *testing.T) {
	sess := plugintest.NewSession(t)
	a := newOrg(t, sess, "acme:1", "acme")
	b := newOrg(t, sess, "acme:2", "acme")
	c := newOrg(t, sess, "globex:1", "globex")
	_, _ = CreateOrgNameClaim(sess, a, "Acme Corp", srcA)
	_, _ = CreateOrgNameClaim(sess, b, "Acme Corp", srcB)
	_, _ = CreateOrgNameClaim(sess, c, "Globex", srcA)

	ids := func(ents []*dbt.Entity) map[string]bool {
		m := map[string]bool{}
		for _, e := range ents {
			m[e.ID] = true
		}
		return m
	}

	// a name claim is found by the name as its sources wrote it
	if got := ids(OrgsSharingName(sess, []string{"Acme Corp"})); len(got) != 2 || !got[a.ID] || !got[b.ID] {
		t.Errorf("OrgsSharingName = %v; want both Acme records", got)
	}
	if got := ids(OrgsSharingIdentifier(sess, a)); len(got) != 1 || !got[b.ID] {
		t.Errorf("OrgsSharingIdentifier = %v; want the other Acme record", got)
	}

	// two contact records with one phone number name a and c
	phone := sess.Asset(t, &oamcon.Phone{Raw: "+1 555 0100", E164: "+15550100", Type: "phone"})
	for i, o := range []*dbt.Entity{a, c} {
		cr := sess.Asset(t, &oamcon.ContactRecord{DiscoveredAt: "https://rdap.example/p" + string(rune('0'+i))})
		sess.Edge(t, cr, &oamgen.SimpleRelation{Name: "phone"}, phone)
		sess.Edge(t, cr, &oamgen.SimpleRelation{Name: "organization"}, o)
	}
	if got := ids(OrgsSharingPhone(sess, a)); len(got) != 1 || !got[c.ID] {
		t.Errorf("OrgsSharingPhone = %v; want globex", got)
	}

	// b's legal address is stored twice as separate records; both count
	addr := oamcon.StreetAddress{Address: "1 Main St, Springfield, IL", BuildingNumber: "1", StreetName: "Main St",
		City: "Springfield", Province: "IL", Country: "US"}
	loc1 := sess.Asset(t, &addr)
	addr2 := addr
	addr2.Address = "1 MAIN ST SPRINGFIELD IL"
	loc2 := sess.Asset(t, &addr2)
	sess.Edge(t, b, &oamgen.SimpleRelation{Name: "legal_address"}, loc1)
	sess.Edge(t, c, &oamgen.SimpleRelation{Name: "hq_address"}, loc2)
	if got := ids(OrgsSharingAddress(sess, b)); len(got) != 1 || !got[c.ID] {
		t.Errorf("OrgsSharingAddress = %v; want globex", got)
	}

	for name, got := range map[string][]*dbt.Entity{
		"identifier": OrgsSharingIdentifier(sess, nil), "phone": OrgsSharingPhone(sess, nil),
		"address": OrgsSharingAddress(sess, nil),
	} {
		if len(got) != 0 {
			t.Errorf("%s with no organization = %v", name, got)
		}
	}
}

func TestOrgForControlledDomain(t *testing.T) {
	sess := plugintest.NewSession(t)
	if OrgForControlledDomain(sess, "") != nil {
		t.Error("an empty domain has an organization")
	}
	if OrgForControlledDomain(sess, "example.com") != nil {
		t.Error("a domain with no website link has an organization")
	}

	orgent := newOrg(t, sess, "acme:1", "acme")
	fqdn := sess.Asset(t, &oamdns.FQDN{Name: "example.com"})
	site := sess.Asset(t, &oamurl.URL{Raw: "https://example.com/", Scheme: "https", Host: "example.com", Path: "/"})
	sess.Edge(t, site, &oamgen.SimpleRelation{Name: "domain"}, fqdn)
	sess.Edge(t, orgent, &oamgen.SimpleRelation{Name: "website"}, site)
	if got := OrgForControlledDomain(sess, "example.com"); got == nil || got.ID != orgent.ID {
		t.Errorf("OrgForControlledDomain = %v; want the organization whose website is on the domain", got)
	}
}
