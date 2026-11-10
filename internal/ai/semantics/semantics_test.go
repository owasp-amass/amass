// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"testing"

	oam "github.com/owasp-amass/open-asset-model"
)

// Every relationship OAM defines must have a meaning, and the table must not
// describe relationships OAM does not have. When OAM gains a relationship,
// this test fails until someone decides its attribution.
func TestTableCoversExactlyTheOAMTaxonomy(t *testing.T) {
	table, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	defined := map[string]bool{}
	for _, src := range oam.AssetList {
		for _, label := range oam.GetAssetOutgoingRelations(src) {
			for _, rt := range oam.RelationList {
				for _, dst := range oam.GetTransformAssetTypes(src, label, rt) {
					k := key(string(src), label, string(rt), string(dst))
					defined[k] = true
					if _, ok := table.index[k]; !ok {
						t.Errorf("no semantics for OAM relationship %s --%s/%s--> %s", src, label, rt, dst)
					}
				}
			}
		}
	}
	for _, r := range table.Relations {
		if !defined[key(r.Source, r.Label, r.RelationType, r.Destination)] {
			t.Errorf("semantics for %s --%s/%s--> %s, which OAM does not define", r.Source, r.Label,
				r.RelationType, r.Destination)
		}
	}
}

func TestParseRejectsBadEntries(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown attribution": "version: 1\nrelations:\n  - {source: A, label: l, relation_type: SimpleRelation, destination: B, attribution: owns, purpose: web, note: x}\n",
		"unknown field":       "version: 1\nrelations:\n  - {source: A, label: l, relation_type: SimpleRelation, destination: B, attribution: controls, purpose: web, note: x, weight: 2}\n",
		"missing note":        "version: 1\nrelations:\n  - {source: A, label: l, relation_type: SimpleRelation, destination: B, attribution: controls, purpose: web}\n",
		"duplicate": "version: 1\nrelations:\n  - {source: A, label: l, relation_type: SimpleRelation, destination: B, attribution: controls, purpose: web, note: x}\n" +
			"  - {source: A, label: l, relation_type: SimpleRelation, destination: B, attribution: controls, purpose: web, note: y}\n",
		"wrong version": "version: 2\nrelations: []\n",
	} {
		if _, err := parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	table, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := table.Lookup("TLSCertificate", "issuer_contact", "SimpleRelation",
		"ContactRecord"); !ok || r.Attribution != ThirdParty {
		t.Fatalf("issuer_contact must be third_party: %+v", r)
	}
	if r, ok := table.Lookup("TLSCertificate", "san_dns_name", "SimpleRelation",
		"FQDN"); !ok || r.Attribution != Shared {
		t.Fatalf("san_dns_name must not carry attribution: %+v", r)
	}
}

// Owner questions rely on every attribution being decided.
func TestNoUndecidedRelationships(t *testing.T) {
	table, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range table.Relations {
		if r.Review {
			t.Errorf("%s --%s--> %s is still marked review: true", r.Source, r.Label, r.Destination)
		}
	}
}

// Registry and protocol endpoints are third parties but never vendors.
func TestRegistryEndpointsAreNotVendors(t *testing.T) {
	table, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := table.Lookup("IPNetRecord", "rdap_url", "SimpleRelation", "URL"); !ok || !r.NotVendor {
		t.Fatalf("rdap_url must be marked vendor: false: %+v", r)
	}
	if r, ok := table.Lookup("DomainRecord", "registrar_contact", "SimpleRelation", "ContactRecord"); !ok ||
		r.NotVendor {
		t.Fatalf("registrar_contact must remain a vendor: %+v", r)
	}
}

func TestParseRejectsVendorFlagOutsideThirdParty(t *testing.T) {
	_, err := parse([]byte(`version: 1
relations:
  - {source: FQDN, label: node, relation_type: SimpleRelation, destination: FQDN,
     attribution: same_subject, purpose: hierarchy, vendor: false, note: "x"}
`))
	if err == nil {
		t.Fatal("vendor flag on a same_subject relationship was accepted")
	}
}
