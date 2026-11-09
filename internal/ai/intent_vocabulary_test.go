// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"reflect"
	"strings"
	"testing"
)

func TestOAMIntentVocabularyCanonicalSynonyms(t *testing.T) {
	selectors := append([]AssetSearchSchema(nil), typedIntentTestCatalog.selectors...)
	for _, kind := range []string{"Location", "TLSCertificate", "Netblock"} {
		selectors = append(selectors, AssetSearchSchema{Type: kind})
	}

	cases := []struct{ words, expected string }{
		{"subdomains", "FQDN"},
		{"hostnames", "FQDN"},
		{"dns names", "FQDN"},
		{"IP addresses", "IPAddress"},
		{"IPv4 addresses", "IPAddress"},
		{"companies", "Organization"},
		{"businesses", "Organization"},
		{"legal entities", "Organization"},
		{"physical addresses", "Location"},
		{"postal addresses", "Location"},
		{"SSL certificates", "TLSCertificate"},
		{"network blocks", "Netblock"},
	}
	for _, tc := range cases {
		got, ok := intentTargetType(tc.words, selectors, typedIntentTestCatalog.rels)
		if !ok || got != tc.expected {
			t.Errorf("%q -> %q (%v); want %q", tc.words, got, ok, tc.expected)
		}
	}
}

func TestOAMIntentVocabularyDoesNotGuessAmbiguousAddresses(t *testing.T) {
	// Register Location explicitly as part of the production schema.
	selectors := append(append([]AssetSearchSchema(nil), typedIntentTestCatalog.selectors...),
		AssetSearchSchema{Type: "Location", Fields: []string{"address"}})
	candidates := intentTypeCandidates("addresses", selectors, typedIntentTestCatalog.rels)
	if !reflect.DeepEqual(candidates, []string{"IPAddress", "Location"}) {
		t.Fatalf("address aliases must remain ambiguous: %+v", candidates)
	}
	if _, ok := intentTargetType("addresses", selectors, typedIntentTestCatalog.rels); ok {
		t.Fatal("unqualified addresses must not resolve without a relationship or other context")
	}
}

func TestOAMIntentAliasesCompileExactRelationshipRoutes(t *testing.T) {
	cat := typedIntentTestCatalog
	cat.selectors = append(append([]AssetSearchSchema(nil), cat.selectors...),
		AssetSearchSchema{Type: "Location", Fields: []string{"address"}})
	cases := []struct{ question, target, direction, label string }{
		{
			"Which companies are connected to tech.acme.example via domain and website relationships?",
			"Organization",
			"in",
			"domain",
		},
		{
			"Which IP addresses are connected to tech.acme.example via dns_record relationships?",
			"IPAddress",
			"out",
			"dns_record",
		},
		{
			"Which addresses are connected to tech.acme.example via dns_record relationships?",
			"IPAddress",
			"out",
			"dns_record",
		},
		{"Which subdomains are connected to tech.acme.example via node relationships?", "FQDN", "out", "node"},
	}
	for _, tc := range cases {
		intent, ok := deterministicTypedRelationIntent(tc.question, cat)
		if !ok || len(intent.Goal.TargetTypes) != 1 || intent.Goal.TargetTypes[0] != tc.target ||
			len(intent.Hops) == 0 || intent.Hops[0].Direction != tc.direction ||
			intent.Hops[0].Label != tc.label {
			t.Errorf("%s compiled to %+v (ok=%v)", tc.question, intent, ok)
		}
	}
}

func TestOAMIntentVocabularyFailsClosedOnCompetingSchemaRoutes(t *testing.T) {
	cat := typedIntentTestCatalog
	cat.selectors = append(append([]AssetSearchSchema(nil), cat.selectors...),
		AssetSearchSchema{Type: "Location", Fields: []string{"address"}})
	cat.rels = append(append([]RelationshipSchema(nil), cat.rels...),
		RelationshipSchema{
			SourceType:      "FQDN",
			Label:           "dns_record",
			RelationType:    "BasicDNSRelation",
			DestinationType: "Location",
		})
	if _, ok := deterministicTypedRelationIntent(
		"Which addresses are connected to tech.acme.example via dns_record relationships?", cat); ok {
		t.Fatal("two valid destination asset types cannot be reduced to a guessed address meaning")
	}
	if _, ok := deterministicTypedRelationIntent(
		"Which subdomains are connected to tech.acme.example via dns_record relationships?", cat); ok {
		t.Fatal("subdomains imply FQDN hierarchy, not an arbitrary DNS relation")
	}
	if _, ok := intentTargetType("domains", cat.selectors, cat.rels); ok {
		t.Fatal("ambiguous domain language should not silently map to FQDN or DomainRecord")
	}
}

func TestOAMIntentVocabularyRespectsActiveSchema(t *testing.T) {
	smallFields := []AssetSearchSchema{{Type: "FQDN", Fields: []string{"name"}}}
	result := intentTypeCandidates("companies", smallFields, nil)
	if len(result) != 0 {
		t.Fatalf("absent catalog types must not be invented: %+v", result)
	}

	vocab := compactIntentVocabulary(smallFields, nil)
	if strings.Contains(vocab, "Organization:") || !strings.Contains(vocab, "FQDN:") {
		t.Fatalf("vocabulary must reflect only active OAM catalog types: %q", vocab)
	}
}
