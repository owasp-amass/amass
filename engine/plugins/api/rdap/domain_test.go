// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"testing"
	"time"

	"github.com/openrdap/rdap"
	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

func rdapDomain() *rdap.Domain {
	signed := true
	return &rdap.Domain{
		Handle:  "EXAMPLE-DOM",
		LDHName: "example.com",
		Status:  []string{"client transfer prohibited"},
		Port43:  "whois.example.com",
		SecureDNS: &rdap.SecureDNS{
			DelegationSigned: &signed,
		},
		Events: []rdap.Event{
			{Action: "registration", Date: "2000-03-01T00:00:00Z"},
			{Action: "last changed", Date: "2024-06-01T12:00:00Z"},
			{Action: "expiration", Date: "2030-03-01T00:00:00Z"},
		},
		Nameservers: []rdap.Nameserver{
			{LDHName: "ns1.example.com"},
			{LDHName: "NS2.EXAMPLE.COM."},
		},
		Entities: []rdap.Entity{
			{
				Handle: "REG-1",
				Roles:  []string{"registrant"},
				VCard: &rdap.VCard{Properties: []*rdap.VCardProperty{
					{Name: "kind", Value: "org"},
					{Name: "fn", Value: "Example Holdings Inc"},
					{Name: "email", Value: "admin@example.com"},
				}},
			},
		},
	}
}

func TestDomainStore(t *testing.T) {
	sess := plugintest.NewSession(t)
	rd := NewRDAP().(*rdapPlugin)
	d := &domain{name: "RDAP-Domain-Handler", plugin: rd}
	fqdn := sess.Asset(t, &oamdns.FQDN{Name: "example.com"})
	e := &et.Event{Session: sess, Entity: fqdn}

	rec := d.store(e, rdapDomain(), fqdn)
	if rec == nil {
		t.Fatal("a complete RDAP domain response was not stored")
	}

	dr, ok := rec.Asset.(*oamreg.DomainRecord)
	if !ok || dr.Domain != "example.com" || dr.ID != "EXAMPLE-DOM" || dr.Extension != "com" ||
		dr.WhoisServer != "whois.example.com" || !dr.DNSSEC || len(dr.Status) != 1 ||
		dr.CreatedDate == "" || dr.UpdatedDate == "" || dr.ExpirationDate == "" {
		t.Fatalf("stored record %+v", rec.Asset)
	}

	ctx := context.Background()
	edges, err := sess.DB().OutgoingEdges(ctx, fqdn, time.Time{}, "registration")
	if err != nil || len(edges) != 1 || edges[0].ToEntity.ID != rec.ID {
		t.Fatalf("registration edge: %v, %v", edges, err)
	}

	tags, err := sess.DB().FindEntityTags(ctx, rec, time.Time{})
	found := false
	for _, tag := range tags {
		if p, ok := tag.Property.(*general.SourceProperty); ok && p.Source == rd.source.Name {
			found = true
		}
	}
	if err != nil || !found {
		t.Errorf("the record lacks its RDAP source: %v, %v", tags, err)
	}
}

// A response with no identifier, dates or status carries nothing beyond the
// name already known, so it is not stored, and malformed event dates do not
// panic the handler.
func TestDomainStoreRejectsEmptyResponses(t *testing.T) {
	sess := plugintest.NewSession(t)
	d := &domain{name: "RDAP-Domain-Handler", plugin: NewRDAP().(*rdapPlugin)}
	fqdn := sess.Asset(t, &oamdns.FQDN{Name: "example.org"})
	e := &et.Event{Session: sess, Entity: fqdn}

	empty := &rdap.Domain{LDHName: "example.org", Events: []rdap.Event{{Action: "registration", Date: "not-a-date"}}}
	if rec := d.store(e, empty, fqdn); rec != nil {
		t.Errorf("an empty response was stored: %+v", rec.Asset)
	}
}

func TestDomainRecordDetail(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(1440)
	sess.Scope().AddDomain("example.com")

	rd := NewRDAP().(*rdapPlugin)
	r := newRecordDetail(rd, oam.DomainRecord)
	drEntity := sess.Asset(t, &oamreg.DomainRecord{Domain: "example.com", WhoisServer: "whois.example.com"})
	e := &et.Event{Session: sess, Entity: drEntity, Dispatcher: &plugintest.Dispatcher{}}

	m, err := sess.Config().CheckTransformations(string(oam.DomainRecord), append(r.transforms, rd.name)...)
	if err != nil {
		t.Fatal(err)
	}

	resp, ok := responseOf(rdapDomain())
	if !ok {
		t.Fatal("the RDAP domain was not read")
	}
	r.store(e, resp, drEntity, m)

	ctx := context.Background()
	// Both name servers, in scope under example.com, are linked.
	ns, err := sess.DB().OutgoingEdges(ctx, drEntity, time.Time{}, "name_server")
	if err != nil || len(ns) != 2 {
		t.Fatalf("name_server edges: %d, %v", len(ns), err)
	}
	for _, edge := range ns {
		a, _ := sess.DB().FindEntityById(ctx, edge.ToEntity.ID)
		if fqdn, ok := a.Asset.(*oamdns.FQDN); !ok || (fqdn.Name != "ns1.example.com" && fqdn.Name != "ns2.example.com") {
			t.Errorf("unexpected name server %+v", a.Asset)
		}
	}

	// The WHOIS server referral is linked.
	if ws, err := sess.DB().OutgoingEdges(ctx, drEntity, time.Time{}, "whois_server"); err != nil || len(ws) != 1 {
		t.Fatalf("whois_server edges: %d, %v", len(ws), err)
	}

	// The registrant is linked with the DomainRecord's registrant_contact
	// label, so the semantics catalog and ownership lens recognize it.
	rc, err := sess.DB().OutgoingEdges(ctx, drEntity, time.Time{}, "registrant_contact")
	if err != nil || len(rc) != 1 {
		t.Fatalf("registrant_contact edges: %d, %v", len(rc), err)
	}

	// The registrant's email address is recorded as an identifier under the
	// contact record, the shared value the ownership signal compares.
	cr, _ := sess.DB().FindEntityById(ctx, rc[0].ToEntity.ID)
	ids, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "id")
	if err != nil || len(ids) != 1 {
		t.Fatalf("contact id edges: %d, %v", len(ids), err)
	}
	idAsset, _ := sess.DB().FindEntityById(ctx, ids[0].ToEntity.ID)
	if id, ok := idAsset.Asset.(*general.Identifier); !ok || id.ID != "admin@example.com" {
		t.Errorf("registrant email identifier %+v", idAsset.Asset)
	}
}
