// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/fingerprint"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/platform"
	"github.com/owasp-amass/open-asset-model/registration"
)

// TestServiceAndReverseDNSSignalsOnSQLite stores services and port
// relations as the HTTP probes and JARM plugin do and checks the redirect,
// TLS fingerprint and reverse DNS signals end to end.
func TestServiceAndReverseDNSSignalsOnSQLite(t *testing.T) {
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "signals.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = db.Close() }()
	checkServiceSignals(t, db)
}

// checkServiceSignals seeds db and checks the service and reverse DNS
// signals found from it.
func checkServiceSignals(t *testing.T, db repository.Repository) {
	t.Helper()

	ctx := context.Background()
	ents := map[string]*dbt.Entity{}
	create := func(name string, a oam.Asset) {
		e, err := db.CreateAsset(ctx, a)
		if err != nil {
			t.Fatal(err)
		}

		ents[name] = e
	}
	link := func(from string, rel oam.Relation, to string) {
		if _, err := db.CreateEdge(ctx, &dbt.Edge{Relation: rel, FromEntity: ents[from], ToEntity: ents[to]}); err != nil {
			t.Fatal(err)
		}
	}
	port := func(n int) oam.Relation {
		return &general.PortRelation{Name: "tcp_port_" + map[int]string{80: "80", 443: "443"}[n], PortNumber: n,
			Protocol: "TCP"}
	}
	// fingerprintID stores a fingerprint as a shared Identifier{idType:value}
	// and a "fingerprint" edge from the named entity, as the collectors do.
	fingerprintID := func(name, idType, value string) {
		id, err := db.CreateAsset(ctx, &general.Identifier{UniqueID: idType + ":" + value, ID: value, Type: idType})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.CreateEdge(ctx, &dbt.Edge{Relation: &general.SimpleRelation{Name: "fingerprint"},
			FromEntity: ents[name], ToEntity: id}); err != nil {
			t.Fatal(err)
		}
	}
	jarm := func(name, hash string) { fingerprintID(name, "JARM", hash) }

	create("owasp", &org.Organization{ID: "owasp", Name: "OWASP Foundation"})
	create("cr-owasp", &contact.ContactRecord{DiscoveredAt: "https://rdap.example/owasp"})
	create("dr", &registration.DomainRecord{Domain: "owasp.org"})
	create("owasp.org", &oamdns.FQDN{Name: "owasp.org"})
	create("www", &oamdns.FQDN{Name: "www.owasp.org"})
	link("cr-owasp", &general.SimpleRelation{Name: "organization"}, "owasp")
	link("dr", &general.SimpleRelation{Name: "registrant_contact"}, "cr-owasp")
	link("owasp.org", &general.SimpleRelation{Name: "registration"}, "dr")
	link("owasp.org", &general.SimpleRelation{Name: "node"}, "www")

	create("svc-www", &platform.Service{ID: "svc-www", Type: "web-service"})
	link("www", port(443), "svc-www")
	jarm("svc-www", "2ad2ad0002ad2ad0042d42d000000ad")
	create("twin", &oamdns.FQDN{Name: "jarm-twin.example"})
	create("svc-twin", &platform.Service{ID: "svc-twin", Type: "web-service"})
	link("twin", port(443), "svc-twin")
	jarm("svc-twin", "2ad2ad0002ad2ad0042d42d000000ad")

	analytics := func(name string) { fingerprintID(name, fingerprint.AnalyticsID, "GTM-K9X2ZQ") }
	analytics("svc-www")
	create("tagged", &oamdns.FQDN{Name: "owasp-tags.example"})
	create("svc-tagged", &platform.Service{ID: "svc-tagged", Type: "web-service"})
	link("tagged", port(443), "svc-tagged")
	analytics("svc-tagged")

	create("redirect", &oamdns.FQDN{Name: "redirect.example"})
	create("svc-redirect", &platform.Service{ID: "svc-redirect", Type: "web-service",
		Attributes: map[string][]string{"Location": {"https://www.owasp.org/welcome"}}})
	link("redirect", port(80), "svc-redirect")

	create("ip", &network.IPAddress{Address: netip.MustParseAddr("203.0.113.5"), Type: "IPv4"})
	link("ip", &general.SimpleRelation{Name: "ptr_record"}, "www")
	create("alumni", &oamdns.FQDN{Name: "alumni-mail.net"})
	link("alumni", &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 1, Class: 1}}, "ip")

	adapter := Adapter{Repo: db}
	owner, err := adapter.GetAsset(ctx, ents["owasp"].ID)
	if err != nil {
		t.Fatal(err)
	}

	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	res, err := review.AttributeOwnership(ctx, adapter, Catalog{}, owner, nil, j, review.AttributionPolicy{Mode: "journal"})
	if err != nil {
		t.Fatal(err)
	}

	got := map[string][]string{}
	for _, c := range res.Report.Candidates {
		for _, s := range c.Signals {
			got[c.Asset] = append(got[c.Asset], s.Signal)
		}
	}
	for asset, want := range map[string]string{
		"jarm-twin.example":  "tls-fingerprint-match",
		"redirect.example":   "web-redirect-to-organization",
		"203.0.113.5":        "reverse-dns-in-namespace",
		"owasp-tags.example": "shared-analytics-id",
		"alumni-mail.net":    "reverse-dns-in-namespace",
	} {
		if !slices.Contains(got[asset], want) {
			t.Errorf("%s signals = %v, want %s (all: %v)", asset, got[asset], want, got)
		}
	}

	// The search answered from a cache finds the same, with fewer reads.
	plain, cached := Adapter{Repo: db, Stats: &ReadStats{}}, Adapter{Repo: db, Stats: &ReadStats{}}
	want, err := lens.SearchOwnershipGaps(ctx, plain, Catalog{}, owner)
	if err != nil {
		t.Fatal(err)
	}
	fromCache, err := lens.SearchOwnershipGaps(ctx, graph.Cached(cached), Catalog{}, owner)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, fromCache) {
		t.Errorf("cached search differs:\n%+v\nwant\n%+v", fromCache, want)
	}
	plainReads, _, plainBy := plain.Stats.Summary()
	cachedReads, _, cachedBy := cached.Stats.Summary()
	if cachedReads >= plainReads {
		t.Errorf("cached search read %d times (%s), uncached %d (%s)", cachedReads, cachedBy, plainReads, plainBy)
	}
}
