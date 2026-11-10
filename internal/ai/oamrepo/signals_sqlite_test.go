// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai"
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
	jarm := func(name, hash string) {
		if _, err := db.CreateEntityProperty(ctx, ents[name], &general.SimpleProperty{PropertyName: "JARM",
			PropertyValue: hash}); err != nil {
			t.Fatal(err)
		}
	}

	create("colgate", &org.Organization{ID: "colgate", Name: "Colgate University"})
	create("cr-colgate", &contact.ContactRecord{DiscoveredAt: "https://rdap.example/colgate"})
	create("dr", &registration.DomainRecord{Domain: "colgate.edu"})
	create("colgate.edu", &oamdns.FQDN{Name: "colgate.edu"})
	create("www", &oamdns.FQDN{Name: "www.colgate.edu"})
	link("cr-colgate", &general.SimpleRelation{Name: "organization"}, "colgate")
	link("dr", &general.SimpleRelation{Name: "registrant_contact"}, "cr-colgate")
	link("colgate.edu", &general.SimpleRelation{Name: "registration"}, "dr")
	link("colgate.edu", &general.SimpleRelation{Name: "node"}, "www")

	create("svc-www", &platform.Service{ID: "svc-www", Type: "web-service"})
	link("www", port(443), "svc-www")
	jarm("svc-www", "2ad2ad0002ad2ad0042d42d000000ad")
	create("twin", &oamdns.FQDN{Name: "jarm-twin.example"})
	create("svc-twin", &platform.Service{ID: "svc-twin", Type: "web-service"})
	link("twin", port(443), "svc-twin")
	jarm("svc-twin", "2ad2ad0002ad2ad0042d42d000000ad")

	create("redirect", &oamdns.FQDN{Name: "redirect.example"})
	create("svc-redirect", &platform.Service{ID: "svc-redirect", Type: "web-service",
		Attributes: map[string][]string{"Location": {"https://www.colgate.edu/welcome"}}})
	link("redirect", port(80), "svc-redirect")

	create("ip", &network.IPAddress{Address: netip.MustParseAddr("203.0.113.5"), Type: "IPv4"})
	link("ip", &general.SimpleRelation{Name: "ptr_record"}, "www")
	create("alumni", &oamdns.FQDN{Name: "alumni-mail.net"})
	link("alumni", &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 1, Class: 1}}, "ip")

	adapter := Adapter{Repo: db}
	owner, err := adapter.GetAsset(ctx, ents["colgate"].ID)
	if err != nil {
		t.Fatal(err)
	}

	j := &ai.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	res, err := ai.AttributeOwnership(ctx, adapter, Catalog{}, owner, nil, j, ai.AttributionPolicy{Mode: "journal"})
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
		"jarm-twin.example": "tls_fingerprint_match",
		"redirect.example":  "web_redirect_to_organization",
		"203.0.113.5":       "reverse_dns_in_namespace",
		"alumni-mail.net":   "reverse_dns_in_namespace",
	} {
		if !slices.Contains(got[asset], want) {
			t.Errorf("%s signals = %v, want %s (all: %v)", asset, got[asset], want, got)
		}
	}
}
