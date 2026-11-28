// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package peeringdb

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/time/rate"
)

func targets(t *testing.T, sess *plugintest.Session, from *dbt.Entity, label string) []*dbt.Entity {
	t.Helper()

	ctx := context.Background()
	edges, err := sess.DB().OutgoingEdges(ctx, from, time.Time{}, label)
	if err != nil {
		return nil
	}
	var out []*dbt.Entity
	for _, edge := range edges {
		if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func property(t *testing.T, sess *plugintest.Session, ent *dbt.Entity, name string) string {
	t.Helper()

	tags, err := sess.DB().FindEntityTags(context.Background(), ent, time.Time{}, name)
	if err != nil || len(tags) == 0 {
		return ""
	}
	return tags[0].Property.Value()
}

// An AS's network record names its operator; the operator's other network
// points at the same record, and the organization is dispatched.
func TestCheckStoresTheOperator(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	web := sess.Web()
	web.Handle("GET www.peeringdb.com/api/net", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Query().Get("asn") == "64500":
			_, _ = io.WriteString(w, `{"data":[{"id":11,"org_id":2,"asn":64500,"name":"Utica Products Net",`+
				`"info_type":"Enterprise","policy_general":"Selective","irr_as_set":"AS-UTICAPRODUCTS"}],"meta":{}}`)
		case r.URL.Query().Get("org_id") == "2":
			_, _ = io.WriteString(w, `{"data":[{"id":11,"org_id":2,"asn":64500},`+
				`{"id":12,"org_id":2,"asn":64501,"info_type":"Content"}],"meta":{}}`)
		default:
			_, _ = io.WriteString(w, `{"data":[],"meta":{}}`)
		}
	})
	web.Reply("GET www.peeringdb.com/api/org/2", http.StatusOK, `{"data":[{"id":2,"name":"Utica Products",`+
		`"website":"https://www.utica-products.example","country":"US"}],"meta":{}}`)

	p := NewPeeringDB().(*peeringDB)
	p.rlimit = rate.NewLimiter(rate.Inf, 1)
	p.log = slog.New(slog.NewTextHandler(io.Discard, nil))

	as := sess.Asset(t, &oamnet.AutonomousSystem{Number: 64500})
	d := &plugintest.Dispatcher{}
	if err := p.check(&et.Event{Entity: as, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}

	crs := targets(t, sess, as, "contact")
	if len(crs) != 1 || crs[0].Asset.(*oamcon.ContactRecord).DiscoveredAt != "https://www.peeringdb.com/org/2" {
		t.Fatalf("the operator record = %v; requests %v", crs, web.Requests())
	}
	orgs := targets(t, sess, crs[0], "organization")
	// the organization is stored under its normalized name
	if len(orgs) != 1 || !strings.EqualFold(orgs[0].Asset.(*oamorg.Organization).Name, "Utica Products") {
		t.Errorf("the operator organization = %v", orgs)
	}
	if len(targets(t, sess, crs[0], "url")) != 1 {
		t.Error("the operator's website was not linked")
	}
	if property(t, sess, as, PropNetworkType) != "Enterprise" || property(t, sess, as, PropPolicy) != "Selective" ||
		property(t, sess, as, PropIRRASSet) != "AS-UTICAPRODUCTS" || property(t, sess, as, PropNetID) != "11" {
		t.Error("the network record's properties were not stored")
	}
	if !slices.ContainsFunc(d.Events(), func(e *et.Event) bool { return e.Entity.Asset.AssetType() == oam.Organization }) {
		t.Errorf("the organization was not dispatched: %v", d.Names())
	}

	sib, err := sess.DB().FindEntitiesByContent(context.Background(), oam.AutonomousSystem, time.Time{}, 1,
		dbt.ContentFilters{"number": 64501})
	if err != nil || len(sib) != 1 {
		t.Fatalf("the sibling network = %v, %v", sib, err)
	}
	if got := targets(t, sess, sib[0], "contact"); len(got) != 1 || got[0].ID != crs[0].ID {
		t.Errorf("the sibling's operator record = %v", got)
	}

	// within the TTL, PeeringDB is not asked again
	before := len(web.Requests())
	if err := p.check(&et.Event{Entity: as, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}
	if len(web.Requests()) != before {
		t.Errorf("asked again within the TTL: %v", web.Requests()[before:])
	}
}

func TestOrganizationAddress(t *testing.T) {
	o := organization{Address1: " 1 Example Way ", City: "Utica", State: "NY", Zipcode: "13501", Country: "US"}
	if got := o.address(); got != "1 Example Way, Utica, NY 13501, US" {
		t.Errorf("address = %q", got)
	}
	if got := (organization{Country: "US"}).address(); got != "US" {
		t.Errorf("a country alone = %q", got)
	}
}
