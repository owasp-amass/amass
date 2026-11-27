// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
)

// linked returns the keys of what from links to with the label.
func linked(t *testing.T, sess *plugintest.Session, from *dbt.Entity, label string) []string {
	t.Helper()

	ctx := context.Background()
	edges, err := sess.DB().OutgoingEdges(ctx, from, time.Time{}, label)
	if err != nil {
		return nil
	}
	var out []string
	for _, edge := range edges {
		if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil {
			out = append(out, a.Asset.Key())
		}
	}
	sort.Strings(out)
	return out
}

func TestStoreContact(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	src := &et.Source{Name: "Test", Confidence: 90}

	ctx := context.Background()
	cr := sess.Asset(t, &contact.ContactRecord{DiscoveredAt: "https://rdap.example.net/entity/EX"})
	m, err := sess.Config().CheckTransformations(string(oam.ContactRecord), string(oam.Identifier),
		string(oam.Phone), string(oam.URL))
	if err != nil {
		t.Fatal(err)
	}

	StoreContact(ctx, sess, cr, Contact{
		Email:   " NOC@Example.NET ",
		Phone:   "+1 315 228 1000",
		Fax:     "+1 315 228 1001",
		Country: "US",
		URL:     "https://example.net/contact",
	}, src, m)

	if got := linked(t, sess, cr, "id"); len(got) != 1 || got[0] != "email:noc@example.net" {
		t.Errorf("email = %v", got)
	}
	if got := linked(t, sess, cr, "phone"); len(got) != 2 {
		t.Errorf("phone and fax = %v", got)
	}
	if got := linked(t, sess, cr, "url"); len(got) != 1 {
		t.Errorf("url = %v", got)
	}

	// The configuration decides what is stored: without Phone, no numbers.
	other := sess.Asset(t, &contact.ContactRecord{DiscoveredAt: "https://rdap.example.net/entity/OTHER"})
	m, err = sess.Config().CheckTransformations(string(oam.ContactRecord), string(oam.Identifier))
	if err != nil {
		t.Fatal(err)
	}
	StoreContact(ctx, sess, other, Contact{Email: "a@example.net", Phone: "+1 315 228 1000"}, src, m)
	if got := linked(t, sess, other, "phone"); len(got) != 0 {
		t.Errorf("phones stored without the Phone transformation: %v", got)
	}
}

func TestLinkContactPerson(t *testing.T) {
	sess := plugintest.NewSession(t)
	src := &et.Source{Name: "Test", Confidence: 90}
	cr := sess.Asset(t, &contact.ContactRecord{DiscoveredAt: "https://example.net/whois"})

	d := &plugintest.Dispatcher{}
	e := &et.Event{Session: sess, Dispatcher: d}
	if p := LinkContactPerson(e, cr, FullNameToPerson("Ada Lovelace"), src); p == nil {
		t.Fatal("no person was created")
	}
	if got := linked(t, sess, cr, "person"); len(got) != 1 {
		t.Errorf("persons = %v", got)
	}
	if len(d.Events()) != 1 {
		t.Errorf("dispatched %v", d.Names())
	}
	if LinkContactPerson(e, cr, nil, src) != nil {
		t.Error("a person with no name was created")
	}
}

func TestRelateAddsASourceToAnExistingEdge(t *testing.T) {
	sess := plugintest.NewSession(t)
	srcA := &et.Source{Name: "SourceA", Confidence: 90}
	srcB := &et.Source{Name: "SourceB", Confidence: 80}

	ctx := context.Background()
	from := sess.Asset(t, &oamdns.FQDN{Name: "example.com"})
	to := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})

	a, err := Relate(ctx, sess, from, &general.SimpleRelation{Name: "node"}, to, srcA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Relate(ctx, sess, from, &general.SimpleRelation{Name: "node"}, to, srcB)
	if err != nil || b.ID != a.ID {
		t.Fatalf("the second relation is %v (%v), want edge %s", b, err, a.ID)
	}
	if !Sourced(ctx, sess, a, time.Time{}, srcA) || !Sourced(ctx, sess, a, time.Time{}, srcB) {
		t.Error("both sources should vouch for the edge")
	}
	if _, err := Relate(ctx, sess, nil, &general.SimpleRelation{Name: "node"}, to, srcA); err == nil {
		t.Error("a relation with no entity was created")
	}
}
