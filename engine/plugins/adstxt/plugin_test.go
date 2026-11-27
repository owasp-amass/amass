// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package adstxt

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/fingerprint"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
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

func TestCheckStoresTheDirectSellerAccounts(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Scope().AddDomain("example.com")

	web := sess.Web()
	web.Reply("GET example.com/ads.txt", http.StatusOK, "contact=ads@example.com\nOWNERDOMAIN=example.com\n"+
		"google.com, pub-1, DIRECT\ngoogle.com, pub-9, DIRECT\nappnexus.com, 1234, RESELLER\n"+
		"rubiconproject.com, 5678, DIRECT\n")
	web.Reply("GET example.com/app-ads.txt", http.StatusNotFound, "")
	web.Reply("GET google.com/sellers.json", http.StatusOK, `{"sellers":[
	  {"seller_id":"pub-1","name":"Example Media Inc.","domain":"example.com","seller_type":"PUBLISHER"}]}`)
	web.Reply("GET rubiconproject.com/sellers.json", http.StatusOK, `{"sellers":[
	  {"seller_id":"5678","name":"Sales House","domain":"saleshouse.com","seller_type":"INTERMEDIARY"}]}`)

	a := NewAdsTxt().(*adsTxt)
	a.rlimit = rate.NewLimiter(rate.Inf, 1)
	a.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	a.catalog = semantics.AdsTxtCatalog()
	a.dir = t.TempDir()

	apex := sess.Asset(t, &oamdns.FQDN{Name: "example.com"})
	e := &et.Event{Entity: apex, Session: sess, Dispatcher: &plugintest.Dispatcher{}}
	if err := a.check(e); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	urls, err := sess.DB().IncomingEdges(ctx, apex, time.Time{}, "domain")
	if err != nil || len(urls) != 1 {
		t.Fatalf("ads.txt URLs = %v, %v; requests %v", urls, err, sess.Web().Requests())
	}
	urlEnt, _ := sess.DB().FindEntityById(ctx, urls[0].FromEntity.ID)

	// The three DIRECT accounts are the file's fingerprints, not the reseller.
	got := map[string]bool{}
	for _, id := range targets(t, sess, urlEnt, "fingerprint") {
		if ident, ok := id.Asset.(*general.Identifier); ok && ident.Type == fingerprint.AdsSeller {
			got[ident.ID] = true
		}
	}
	if len(got) != 3 || !got["google.com:pub-1"] || !got["google.com:pub-9"] || !got["rubiconproject.com:5678"] {
		t.Errorf("fingerprints = %v", got)
	}

	// The file's owner contact.
	crs := targets(t, sess, urlEnt, "contact")
	if len(crs) != 1 || len(targets(t, sess, crs[0], "fqdn")) != 1 || len(targets(t, sess, crs[0], "id")) != 1 {
		t.Errorf("the owner contact record = %v", crs)
	}

	// The sellers.json accounts: the publisher with its name, the
	// intermediary with only its domain; pub-9 is not listed.
	accts, err := sess.DB().FindEntitiesByType(ctx, oam.Account, time.Now().Add(-time.Hour), 10)
	if err != nil || len(accts) != 2 {
		t.Fatalf("seller accounts = %v, %v", accts, err)
	}
	for _, acct := range accts {
		cr := targets(t, sess, acct, "contact")
		if len(cr) != 1 {
			t.Errorf("contacts of %v = %v", acct.Asset, cr)
			continue
		}
		orgs := targets(t, sess, cr[0], "organization")
		switch acct.Asset.(*oamacct.Account).ID {
		case "google.com:pub-1":
			if len(orgs) != 1 {
				t.Errorf("the publisher's organization = %v", orgs)
			}
		case "rubiconproject.com:5678":
			if len(orgs) != 0 {
				t.Errorf("the intermediary named an organization: %v", orgs)
			}
		}
	}

	// Within the TTL the domain is not fetched again, and the two google.com
	// accounts read one sellers.json.
	sent := len(sess.Web().Requests())
	if err := a.check(e); err != nil {
		t.Fatal(err)
	}
	if len(sess.Web().Requests()) != sent {
		t.Errorf("the domain was fetched again within the TTL")
	}
	var googles int
	for _, r := range sess.Web().Requests() {
		if r == "GET google.com/sellers.json" {
			googles++
		}
	}
	if googles != 1 {
		t.Errorf("google.com/sellers.json was read %d times", googles)
	}
}
