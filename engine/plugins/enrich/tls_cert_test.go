// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// related returns the keys of the assets the entity points to with the
// label, sorted, and fails when an edge lacks the expected source.
func related(t *testing.T, sess *plugintest.Session, from *dbt.Entity, label string, src *et.Source) ([]string, []*dbt.Entity) {
	t.Helper()

	ctx := context.Background()
	edges, err := sess.DB().OutgoingEdges(ctx, from, time.Time{}, label)
	if err != nil {
		return nil, nil
	}

	var keys []string
	var ents []*dbt.Entity
	for _, edge := range edges {
		if src != nil && !support.Sourced(ctx, sess, edge, time.Time{}, src) {
			t.Errorf("the %s edge is not tagged with %s", label, src.Name)
		}
		if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil {
			keys = append(keys, a.Asset.Key())
			ents = append(ents, a)
		}
	}
	sort.Strings(keys)
	return keys, ents
}

func TestTLSCertExpansionStoresTheCertificateRelations(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)

	san, _ := url.Parse("https://portal.example.com/login")
	cert := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(4242),
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		Subject: pkix.Name{
			CommonName:         "www.example.com",
			Organization:       []string{"Acme Widgets Inc"},
			OrganizationalUnit: []string{"See https://www.example.com/about"},
			StreetAddress:      []string{"1 Main St"},
			Locality:           []string{"San Francisco"},
			Province:           []string{"CA"},
			PostalCode:         []string{"94105"},
			Country:            []string{"US"},
		},
		// The issuer names an organization without an address.
		Issuer:                pkix.Name{CommonName: "Example Issuing CA", Organization: []string{"Northwind Trust Services"}},
		DNSNames:              []string{"www.example.com", " API.Example.com "},
		EmailAddresses:        []string{"Admin@Example.com", " "},
		IPAddresses:           []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::1")},
		URIs:                  []*url.URL{san},
		IssuingCertificateURL: []string{"http://ca.example.net/issuer.crt"},
		OCSPServer:            []string{"http://ocsp.example.net"},
	}

	te := NewTLSCerts().(*tlsexpand)
	te.log = slog.New(slog.NewTextHandler(io.Discard, nil))

	certEnt := sess.Asset(t, support.X509ToOAMTLSCertificate(cert))
	first := &plugintest.Dispatcher{}
	if err := te.check(&et.Event{Entity: certEnt, Meta: cert, Session: sess, Dispatcher: first}); err != nil {
		t.Fatal(err)
	}

	for label, want := range map[string]string{
		"common_name":             "www.example.com",
		"san_dns_name":            "api.example.com www.example.com",
		"san_email_address":       "email:admin@example.com",
		"san_ip_address":          "192.0.2.10 2001:db8::1",
		"san_url":                 "https://portal.example.com/login",
		"issuing_certificate_url": "http://ca.example.net/issuer.crt",
		"ocsp_server":             "http://ocsp.example.net",
	} {
		if got, _ := related(t, sess, certEnt, label, te.source); strings.Join(got, " ") != want {
			t.Errorf("%s = %v, want %s", label, got, want)
		}
	}

	// Each party to the certificate is a contact record with its organization.
	for label, wantOrg := range map[string]string{
		"subject_contact": "Acme Widgets Inc",
		"issuer_contact":  "Northwind Trust Services",
	} {
		keys, crs := related(t, sess, certEnt, label, te.source)
		role := map[string]string{"subject_contact": "Subject", "issuer_contact": "Issuer"}[label]
		if len(crs) != 1 || keys[0] != support.X509ContactKey(cert, role) {
			t.Fatalf("%s = %v", label, keys)
		}
		if _, ok := crs[0].Asset.(*contact.ContactRecord); !ok {
			t.Fatalf("%s is a %T", label, crs[0].Asset)
		}

		_, orgs := related(t, sess, crs[0], "organization", nil)
		if len(orgs) != 1 {
			t.Fatalf("%s organizations = %d", label, len(orgs))
		}
		if o := orgs[0].Asset.(*oamorg.Organization); semantics.OrgNameKey(o.Name) != semantics.OrgNameKey(wantOrg) {
			t.Errorf("%s organization = %q, want %q", label, o.Name, wantOrg)
		}

		// Only the subject's unit carries a web address.
		urls, _ := related(t, sess, crs[0], "url", nil)
		if label == "subject_contact" && strings.Join(urls, " ") != "https://www.example.com/about" {
			t.Errorf("subject contact URLs = %v", urls)
		} else if label == "issuer_contact" && len(urls) != 0 {
			t.Errorf("issuer contact URLs = %v", urls)
		}
	}

	var orgEvents int
	for _, ev := range first.Events() {
		if ev.Entity != nil && ev.Entity.Asset.AssetType() == oam.Organization {
			orgEvents++
		}
	}
	if orgEvents != 2 {
		t.Errorf("organization events = %d, want 2; events %v", orgEvents, first.Names())
	}

	// Without the parsed certificate, the stored relations are sent on again
	// within the time to live: the 9 names, addresses and URLs and the 2 contacts.
	again := &plugintest.Dispatcher{}
	if err := te.check(&et.Event{Entity: certEnt, Session: sess, Dispatcher: again}); err != nil {
		t.Fatal(err)
	}
	if n := len(again.Events()); n != 11 {
		t.Errorf("stored relations sent on = %d, want 11; events %v", n, again.Names())
	}
}
