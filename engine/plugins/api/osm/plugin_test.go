// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package osm

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/time/rate"
)

// newTestOSM serves Overpass: a name query gets sampleOverpass, a phone query
// a feature carrying the number, and an address query features on the street.
func newTestOSM(t *testing.T) (*openstreetmap, *plugintest.Session, *[]string) {
	t.Helper()

	sess := plugintest.NewSession(t)
	sess.TTL(60)

	var queries []string
	sess.Web().Handle("POST overpass-api.de/api/interpreter", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		q := r.PostForm.Get("data")
		queries = append(queries, q)

		switch {
		case strings.Contains(q, `["name"~`):
			_, _ = io.WriteString(w, sampleOverpass)
		case strings.Contains(q, `["phone"~`):
			_, _ = io.WriteString(w, `{"elements":[
			  {"type":"node","id":1,"tags":{"name":"Utica Coffee","phone":"+1 (315) 555-5555"}},
			  {"type":"node","id":2,"tags":{"name":"Near Miss","phone":"+1 315 555 55551"}},
			  {"type":"node","id":3,"tags":{"phone":"+1 315 555 5555"}}
			]}`)
		case strings.Contains(q, `["addr:street"~`):
			_, _ = io.WriteString(w, `{"elements":[
			  {"type":"way","id":4,"tags":{"name":"Utica Books","addr:street":"Main Street","addr:housenumber":"13"}},
			  {"type":"way","id":5,"tags":{"name":"Other Shop","addr:street":"Main Street","addr:housenumber":"15"}}
			]}`)
		default:
			_, _ = io.WriteString(w, `{"elements":[]}`)
		}
	})

	o := NewOpenStreetMap().(*openstreetmap)
	o.rlimit = rate.NewLimiter(rate.Inf, 1)
	o.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	o.phones = &phones{name: o.name + "-Phones-Handler", plugin: o}
	o.reverse = &reverse{name: o.name + "-Reverse-Handler", plugin: o}
	return o, sess, &queries
}

// contactTargets returns what the contact records naming the organization
// link to with the label.
func contactTargets(t *testing.T, sess *plugintest.Session, orgent *dbt.Entity, label string) []*dbt.Entity {
	t.Helper()

	ctx := context.Background()
	crs, err := sess.DB().IncomingEdges(ctx, orgent, time.Time{}, "organization")
	if err != nil {
		return nil
	}
	var out []*dbt.Entity
	for _, cr := range crs {
		from, err := sess.DB().FindEntityById(ctx, cr.FromEntity.ID)
		if err != nil {
			continue
		}
		edges, err := sess.DB().OutgoingEdges(ctx, from, time.Time{}, label)
		if err != nil {
			continue
		}
		for _, edge := range edges {
			if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil {
				out = append(out, a)
			}
		}
	}
	return out
}

func TestPhonesStoresTheOrganizationsNumbers(t *testing.T) {
	o, sess, queries := newTestOSM(t)
	orgent := sess.Asset(t, &oamorg.Organization{ID: "owasp:test", Name: "owasp foundation"})
	sess.Scope().Add(orgent.Asset)

	d := &plugintest.Dispatcher{}
	e := &et.Event{Entity: orgent, Session: sess, Dispatcher: d}
	if err := o.phones.check(e); err != nil {
		t.Fatal(err)
	}

	// The three numbers of the two features named for the university, not the
	// inn's.
	got := map[string]bool{}
	for _, a := range contactTargets(t, sess, orgent, "phone") {
		got[a.Asset.(*contact.Phone).E164] = true
	}
	if len(got) != 3 || !got["+13155551000"] || !got["+13155557000"] || !got["+13155557001"] || got["+13155550000"] {
		t.Errorf("phones = %v", got)
	}
	if len(d.Events()) != 3 {
		t.Errorf("dispatched %v", d.Names())
	}

	// The organization is monitored: no second query within the TTL.
	if err := o.phones.check(e); err != nil {
		t.Fatal(err)
	}
	if len(*queries) != 1 {
		t.Errorf("queries = %d", len(*queries))
	}
}

func TestReverseFindsTheOrganizationsAtAPhone(t *testing.T) {
	o, sess, _ := newTestOSM(t)
	phone := sess.Asset(t, &contact.Phone{Raw: "+1 315 555 5555", E164: "+13155555555", Type: contact.PhoneTypeRegular})

	d := &plugintest.Dispatcher{}
	if err := o.reverse.checkPhone(&et.Event{Entity: phone, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}

	// Only the named feature with exactly the number; not the longer number
	// the regex also matched, nor the unnamed feature.
	evs := d.Events()
	if len(evs) != 1 {
		t.Fatalf("dispatched %v", d.Names())
	}
	if phones := contactTargets(t, sess, evs[0].Entity, "phone"); len(phones) != 1 || phones[0].ID != phone.ID {
		t.Errorf("the organization does not reach the phone: %v", phones)
	}
}

func TestReverseFindsTheOrganizationsAtAnAddress(t *testing.T) {
	o, sess, queries := newTestOSM(t)
	addr := &contact.StreetAddress{Address: "13 Main Street Utica NY", BuildingNumber: "13",
		StreetName: "Main Street", City: "Utica"}
	loc := sess.Asset(t, addr)

	d := &plugintest.Dispatcher{}
	if err := o.reverse.checkAddress(&et.Event{Entity: loc, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains((*queries)[0], `["addr:housenumber"="13"]`) {
		t.Errorf("query = %s", (*queries)[0])
	}

	// The shop at number 13, not the one at 15.
	evs := d.Events()
	if len(evs) != 1 {
		t.Fatalf("dispatched %v", d.Names())
	}
	if addrs := contactTargets(t, sess, evs[0].Entity, "street_address"); len(addrs) != 1 || addrs[0].ID != loc.ID {
		t.Errorf("the organization does not reach the address: %v", addrs)
	}

	// An address with no street is skipped.
	bare := sess.Asset(t, &contact.StreetAddress{Address: "Utica NY", City: "Utica"})
	if err := o.reverse.checkAddress(&et.Event{Entity: bare, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}
	if len(*queries) != 1 {
		t.Errorf("queries = %d", len(*queries))
	}
}
