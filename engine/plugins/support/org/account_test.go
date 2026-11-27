// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func TestOrgCheckingAccountIsSharedBySources(t *testing.T) {
	sess := plugintest.NewSession(t)
	srcA := &et.Source{Name: "SourceA", Confidence: 90}
	srcB := &et.Source{Name: "SourceB", Confidence: 80}

	orgent := sess.Asset(t, &oamorg.Organization{ID: "acme:test", Name: "acme", Active: true})
	a := OrgCheckingAccount(sess, orgent, srcA)
	if a == nil {
		t.Fatal("no account was created")
	}
	if acc := a.Asset.(*oamacct.Account); acc.Type != oamacct.Checking || acc.Number != "default" || !acc.Active {
		t.Errorf("account = %+v", acc)
	}

	// A second source finds the same account and vouches for its edge too.
	if b := OrgCheckingAccount(sess, orgent, srcB); b == nil || b.ID != a.ID {
		t.Fatalf("the second source got %v, want %s", b, a.ID)
	}
	ctx := context.Background()
	edges, err := sess.DB().OutgoingEdges(ctx, orgent, time.Time{}, "account")
	if err != nil || len(edges) != 1 {
		t.Fatalf("account edges = %v, %v", edges, err)
	}
	for _, src := range []*et.Source{srcA, srcB} {
		if !support.Sourced(ctx, sess, edges[0], time.Time{}, src) {
			t.Errorf("%s does not vouch for the account edge", src.Name)
		}
	}

	if OrgCheckingAccount(sess, a, srcA) != nil {
		t.Error("an account was made for an entity that is not an organization")
	}
}

func TestOrgTransfersReceivedKeepsToTheSource(t *testing.T) {
	sess := plugintest.NewSession(t)
	srcA := &et.Source{Name: "SourceA", Confidence: 90}
	srcB := &et.Source{Name: "SourceB", Confidence: 80}

	orgent := sess.Asset(t, &oamorg.Organization{ID: "acme:test", Name: "acme"})
	acct := OrgCheckingAccount(sess, orgent, srcA)
	transfer := func(id string, src *et.Source) {
		f := sess.Asset(t, &oamfin.FundsTransfer{ID: id, Amount: 100, Currency: "USD"})
		if _, err := support.Relate(context.Background(), sess, f, &oamgen.SimpleRelation{Name: "recipient"}, acct, src); err != nil {
			t.Fatal(err)
		}
	}
	transfer("a-1", srcA)
	transfer("a-2", srcA)
	transfer("b-1", srcB)

	since := time.Now().Add(-time.Hour)
	got := map[string]bool{}
	for _, ent := range OrgTransfersReceived(sess, orgent, since, srcA) {
		got[ent.Asset.(*oamfin.FundsTransfer).ID] = true
	}
	if len(got) != 2 || !got["a-1"] || !got["a-2"] {
		t.Errorf("SourceA's transfers = %v, want a-1 and a-2", got)
	}

	// SourceB recorded a transfer but never vouched for the account edge, so
	// it finds nothing.
	if ents := OrgTransfersReceived(sess, orgent, since, srcB); len(ents) != 0 {
		t.Errorf("SourceB found %d transfers through an account edge it never recorded", len(ents))
	}
}

func TestStoreReceivedTransfer(t *testing.T) {
	sess := plugintest.NewSession(t)
	src := &et.Source{Name: "Grants", Confidence: 90}
	orgent := sess.Asset(t, &oamorg.Organization{ID: "acme:test", Name: "acme", Active: true})
	e := &et.Event{Entity: orgent, Session: sess, Dispatcher: &plugintest.Dispatcher{}}

	// Nothing is stored without an ID or a positive amount.
	for _, bad := range []ReceivedTransfer{
		{Amount: 100},
		{ID: "grant:zero"},
		{ID: "grant:negative", Amount: -5},
	} {
		if got := StoreReceivedTransfer(e, orgent, bad, src); got != nil {
			t.Errorf("%+v was stored", bad)
		}
	}

	fundent := StoreReceivedTransfer(e, orgent, ReceivedTransfer{
		ID: "grant:1", Reference: "G-1", Amount: 2500, Date: "2026-03-04", Funder: " National Science Foundation ",
	}, src)
	if fundent == nil {
		t.Fatal("the transfer was not stored")
	}
	f := fundent.Asset.(*oamfin.FundsTransfer)
	if f.Currency != "USD" || f.ReferenceNumber != "G-1" || f.Amount != 2500 || f.ExchangeDate == "" {
		t.Errorf("transfer = %+v", f)
	}

	// The organization's checking account received it, as src says.
	if got := OrgTransfersReceived(sess, orgent, time.Time{}, src); len(got) != 1 || got[0].ID != fundent.ID {
		t.Errorf("transfers received = %v", got)
	}

	ctx := context.Background()
	edges, err := sess.DB().OutgoingEdges(ctx, fundent, time.Time{}, "third_party")
	if err != nil || len(edges) != 1 {
		t.Fatalf("funder edges = %v, %v", edges, err)
	}
	funder, err := sess.DB().FindEntityById(ctx, edges[0].ToEntity.ID)
	if err != nil {
		t.Fatal(err)
	}
	if o := funder.Asset.(*oamorg.Organization); o.Name == "" || !support.Sourced(ctx, sess, edges[0], time.Time{}, src) {
		t.Errorf("funder = %+v", o)
	}

	disp := &plugintest.Dispatcher{}
	DispatchTransfers(&et.Event{Session: sess, Dispatcher: disp}, fundent)
	if names := disp.Names(); len(names) != 1 || names[0] != "2500.000000:grant:1" {
		t.Errorf("dispatched %v", names)
	}
}
