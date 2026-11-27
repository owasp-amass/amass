// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

var (
	srcA = &et.Source{Name: "SourceA", Confidence: 90}
	srcB = &et.Source{Name: "SourceB", Confidence: 80}
)

func newOrg(t *testing.T, sess *plugintest.Session, id, name string) *dbt.Entity {
	t.Helper()
	return sess.Asset(t, &oamorg.Organization{ID: id, Name: name})
}

// Every identifier claim is found again by the source that made it, and not
// by another source.
func TestIdentifierClaims(t *testing.T) {
	for name, c := range map[string]struct {
		create func(et.Session, *dbt.Entity, string, *et.Source) (*dbt.Entity, error)
		find   func(et.Session, string, *et.Source) (*dbt.Entity, error)
		value  string
	}{
		"name":        {CreateOrgNameClaim, FindOrgByNameClaim, "Acme Corp"},
		"legal name":  {CreateOrgLegalNameClaim, FindOrgByLegalNameClaim, "Acme Corporation, Inc."},
		"LEI":         {CreateOrgLEICode, FindOrgByLEICode, "5493001KJTIIGC8Y1R12"},
		"RDAP handle": {CreateOrgRDAPHandle, FindOrgByRDAPHandle, "ACME-1"},
	} {
		t.Run(name, func(t *testing.T) {
			sess := plugintest.NewSession(t)
			orgent := newOrg(t, sess, "acme:1", "acme")

			ident, err := c.create(sess, orgent, c.value, srcA)
			if err != nil || ident == nil {
				t.Fatalf("create: %v", err)
			}
			got, err := c.find(sess, c.value, srcA)
			if err != nil || got.ID != orgent.ID {
				t.Fatalf("find = %v, %v; want the organization", got, err)
			}
			if _, err := c.find(sess, c.value, srcB); err == nil {
				t.Error("another source's claim was found")
			}
			if _, err := c.find(sess, c.value+"x", srcA); err == nil {
				t.Error("a value never claimed was found")
			}
		})
	}
}

func TestJurisdictionsCompatible(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"US", "US", true},
		{"us", "US", true},
		{"US", "US-DE", true},
		{"US-DE", "US", true},
		{"US-DE", "US-CA", true},
		{"US-DE", "us-de", true},
		{"US", "GB", false},
		{"US-DE", "GB-ENG", false},
		{"", "US", false},
		{"US", "", false},
	} {
		if got := jurisdictionsCompatible(c.a, c.b); got != c.want {
			t.Errorf("jurisdictionsCompatible(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// Of several organizations sharing a normalized name, the one with a
// compatible jurisdiction is found, from any source.
func TestFindOrgByNormNameAndJurisdictionClaim(t *testing.T) {
	sess := plugintest.NewSession(t)
	gb := newOrg(t, sess, "acme:gb", "acme")
	us := newOrg(t, sess, "acme:us", "acme")
	if err := CreateOrgJurisdictionClaim(sess, gb, "GB"); err != nil {
		t.Fatal(err)
	}
	if err := CreateOrgJurisdictionClaim(sess, us, "US-DE"); err != nil {
		t.Fatal(err)
	}

	if got, err := FindOrgByNormNameAndJurisdictionClaim(sess, "acme", "US"); err != nil || got.ID != us.ID {
		t.Errorf("US = %v, %v; want the Delaware record", got, err)
	}
	if got, err := FindOrgByNormNameAndJurisdictionClaim(sess, "acme", "GB-ENG"); err != nil || got.ID != gb.ID {
		t.Errorf("GB-ENG = %v, %v; want the GB record", got, err)
	}
	if _, err := FindOrgByNormNameAndJurisdictionClaim(sess, "acme", "FR"); err == nil {
		t.Error("an incompatible jurisdiction matched")
	}
	if _, err := FindOrgByNormNameAndJurisdictionClaim(sess, "globex", "US"); err == nil {
		t.Error("an unknown name matched")
	}
}

// A registration number is found with a compatible jurisdiction, from any
// source, and not with another country's.
func TestFindOrgByJurisdictionAndRegistrationIDClaim(t *testing.T) {
	sess := plugintest.NewSession(t)
	orgent := newOrg(t, sess, "acme:1", "acme")
	if _, err := CreateOrgRegistrationIDClaim(sess, orgent, "5551234", srcA); err != nil {
		t.Fatal(err)
	}
	if err := CreateOrgJurisdictionClaim(sess, orgent, "US-DE"); err != nil {
		t.Fatal(err)
	}

	for _, j := range []string{"US-DE", "US"} {
		if got, err := FindOrgByJurisdictionAndRegistrationIDClaim(sess, j, "5551234"); err != nil || got.ID != orgent.ID {
			t.Errorf("%s: %v, %v", j, got, err)
		}
	}
	if _, err := FindOrgByJurisdictionAndRegistrationIDClaim(sess, "GB", "5551234"); err == nil {
		t.Error("another country's registry matched")
	}
	if _, err := FindOrgByJurisdictionAndRegistrationIDClaim(sess, "US-DE", "999"); err == nil {
		t.Error("an unknown number matched")
	}
}

// An identifier is stored only when every matched record agrees on it.
func TestStoreUnambiguousIdentifier(t *testing.T) {
	for name, c := range map[string]struct {
		values []string
		want   string
	}{
		"agreeing":           {[]string{"abc123", "", " ABC123 "}, "ABC123"},
		"conflicting":        {[]string{"ABC123", "XYZ789"}, ""},
		"none":               {[]string{"", " "}, ""},
		"one with the empty": {[]string{"", "DEF456"}, "DEF456"},
	} {
		t.Run(name, func(t *testing.T) {
			sess := plugintest.NewSession(t)
			orgent := newOrg(t, sess, "acme:1", "acme")

			StoreUnambiguousIdentifier(sess, orgent, UEIIdentifier, c.values, srcA)
			got, err := findOrgByIDClaim(sess, UEIIdentifier, c.want, srcA)
			if c.want == "" {
				edges, _ := sess.DB().OutgoingEdges(context.Background(), orgent, time.Time{}, "id")
				if len(edges) != 0 {
					t.Errorf("an identifier was stored from %q", c.values)
				}
				return
			}
			if err != nil || got.ID != orgent.ID {
				t.Errorf("the identifier %s was not stored: %v", c.want, err)
			}
		})
	}
}
