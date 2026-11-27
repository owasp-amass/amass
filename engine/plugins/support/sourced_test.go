// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

func TestSourced(t *testing.T) {
	sess := plugintest.NewSession(t)
	srcA := &et.Source{Name: "SourceA", Confidence: 90}
	srcB := &et.Source{Name: "SourceB", Confidence: 80}

	ctx := context.Background()
	from := sess.Asset(t, &oamdns.FQDN{Name: "example.com"})
	to := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	edge := Link(ctx, sess, from, "node", to, srcA)
	if edge == nil {
		t.Fatal("the edge was not created")
	}

	if !Sourced(ctx, sess, edge, time.Time{}, srcA) {
		t.Error("the source that created the edge does not vouch for it")
	}
	if Sourced(ctx, sess, edge, time.Time{}, srcB) {
		t.Error("another source vouches for the edge")
	}
	if Sourced(ctx, sess, edge, time.Time{}, nil) || Sourced(ctx, sess, nil, time.Time{}, srcA) {
		t.Error("a missing source or edge is vouched for")
	}
}

func TestStoredFindings(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	src := &et.Source{Name: "SourceA", Confidence: 90}
	other := &et.Source{Name: "SourceB", Confidence: 80}

	ctx := context.Background()
	cr := sess.Asset(t, &contact.ContactRecord{DiscoveredAt: "https://example.com/contact"})
	email := sess.Asset(t, &oamgen.Identifier{UniqueID: "email:a@example.com", ID: "a@example.com", Type: oamgen.EmailAddress})
	phone := sess.Asset(t, &contact.Phone{Raw: "+1 555 0100", E164: "+15550100", Type: contact.PhoneTypeRegular})
	url := sess.Asset(t, &oamdns.FQDN{Name: "example.com"})
	Link(ctx, sess, cr, "id", email, src)
	Link(ctx, sess, cr, "phone", phone, other)
	Link(ctx, sess, cr, "url", url, src) // not a label of the matched types

	e := &et.Event{Entity: cr, Session: sess, Dispatcher: &plugintest.Dispatcher{}}
	m, err := sess.Config().CheckTransformations(string(oam.ContactRecord), string(oam.Identifier), string(oam.Phone))
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string][]string{
		string(oam.Identifier): {"id"},
		string(oam.Phone):      {"phone"},
	}

	// Only the edge the source vouched for.
	got := StoredFindings(e, cr, "ContactRecord", "Test", m, labels, src)
	if len(got) != 1 || got[0].To.ID != email.ID || got[0].FromName != "ContactRecord" || got[0].ToName != "email:a@example.com" {
		t.Fatalf("findings = %+v", got)
	}

	// Without a source, every source's edges with the labels.
	if got := StoredFindings(e, cr, "ContactRecord", "Test", m, labels, nil); len(got) != 2 {
		t.Errorf("findings from any source = %+v", got)
	}

	// A type the configuration does not match contributes no labels.
	m, err = sess.Config().CheckTransformations(string(oam.ContactRecord), string(oam.Phone))
	if err != nil {
		t.Fatal(err)
	}
	if got := StoredFindings(e, cr, "ContactRecord", "Test", m, map[string][]string{
		string(oam.Identifier): {"id"},
	}, src); len(got) != 0 {
		t.Errorf("findings for an unmatched type = %+v", got)
	}
}
