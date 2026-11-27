// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/open-asset-model/contact"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func TestStoreDomainIdentity(t *testing.T) {
	sess := plugintest.NewSession(t)
	wiki := &et.Source{Name: "Wikidata", Confidence: 85}
	site := &et.Source{Name: "SchemaOrg", Confidence: 50}

	// The first source creates the organization and ties it to the domain
	// through its website, and links the LEI.
	d := &plugintest.Dispatcher{}
	e := &et.Event{Session: sess, Dispatcher: d}
	first := StoreDomainIdentity(e, "utica-products.com", DomainIdentity{Name: "Utica Products",
		LegalName: "Productos Económicos de Utica, S.A.B. de C.V.", Website: "http://utica-products.com/",
		LEI: "5493000UTICAPROD0001"}, wiki)
	if first == nil {
		t.Fatal("no organization was stored")
	}
	if OrgForControlledDomain(sess, "utica-products.com") == nil {
		t.Error("the organization is not reachable from the domain")
	}
	lei := oamgen.LEICode + ":5493000UTICAPROD0001"
	if !slices.Contains(d.Names(), lei) {
		t.Errorf("the LEI was not dispatched: %v", d.Names())
	}

	// A second source reuses it, filling the unset jurisdiction.
	second := StoreDomainIdentity(&et.Event{Session: sess, Dispatcher: &plugintest.Dispatcher{}}, "utica-products.com",
		DomainIdentity{Name: "Utica Products", Country: "MX"}, site)
	if second == nil || second.ID != first.ID {
		t.Fatalf("the second source got %v, want %s", second, first.ID)
	}
	if o := second.Asset.(*oamorg.Organization); o.Jurisdiction != "MX" {
		t.Errorf("jurisdiction = %q", o.Jurisdiction)
	}

	// No name, nothing stored.
	if StoreDomainIdentity(e, "example.com", DomainIdentity{LEI: "X"}, wiki) != nil {
		t.Error("an identity with no name was stored")
	}
}

func TestDomainIdentityBestName(t *testing.T) {
	if n := (DomainIdentity{Name: "Utica Products", LegalName: " Productos "}).BestName(); n != "Productos" {
		t.Errorf("BestName = %q", n)
	}
	if n := (DomainIdentity{Name: " Utica Products "}).BestName(); n != "Utica Products" {
		t.Errorf("BestName = %q", n)
	}
}

func TestLinkContactOrg(t *testing.T) {
	sess := plugintest.NewSession(t)
	src := &et.Source{Name: "WHOIS", Confidence: 100}
	cr := sess.Asset(t, &contact.ContactRecord{DiscoveredAt: "https://whois.example.net/example.com registrant"})

	d := &plugintest.Dispatcher{}
	e := &et.Event{Session: sess, Dispatcher: d}
	orgent := LinkContactOrg(e, cr, " Example Holdings, Inc. ", src)
	if orgent == nil {
		t.Fatal("no organization was created")
	}
	if !linked(t, sess, cr, "organization", orgent) {
		t.Error("the contact record does not name the organization")
	}
	if len(d.Events()) != 1 {
		t.Errorf("dispatched %v", d.Names())
	}
	if LinkContactOrg(e, cr, "  ", src) != nil {
		t.Error("an organization with no name was created")
	}
}
