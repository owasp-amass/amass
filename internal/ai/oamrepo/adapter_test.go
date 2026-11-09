// SPDX-License-Identifier: Apache-2.0
package oamrepo

import (
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"testing"
)

func TestSourceIdentityExcludesConfidence(t *testing.T) {
	low := &general.SourceProperty{Source: "registrar-example", Confidence: 30}
	high := &general.SourceProperty{Source: "registrar-example", Confidence: 95}
	if source(low) != source(high) || source(low) != "registrar-example" {
		t.Fatalf("source identity incorrectly depends on confidence: %q vs %q", source(low), source(high))
	}
	other := &general.SimpleProperty{PropertyName: "registrar-example", PropertyValue: "yes"}
	if source(other) != "" {
		t.Fatal("non-source properties counted as independent provenance")
	}
}

func TestOAMCatalogContainsSubsidiaryWebsitePaths(t *testing.T) {
	relations := (Catalog{}).Relations()
	check := func(source, label, relationType, destination string) {
		t.Helper()
		for _, r := range relations {
			if r.SourceType == source && r.Label == label &&
				r.RelationType == relationType && r.DestinationType == destination {
				return
			}
		}
		t.Fatalf("OAM catalog missing %s -%s(%s)-> %s", source, label, relationType, destination)
	}
	check("Organization", "subsidiary", "SimpleRelation", "Organization")
	check("Organization", "website", "SimpleRelation", "URL")
	check("URL", "domain", "SimpleRelation", "FQDN")
}

func TestEveryOAMAssetHasARegisteredRootSelector(t *testing.T) {
	schemas := (Catalog{}).SearchFields()
	byType := map[string]bool{}
	for _, schema := range schemas {
		byType[schema.Type] = true
	}
	for _, assetType := range oam.AssetList {
		if !byType[string(assetType)] {
			t.Errorf("missing selector schema for %s", assetType)
		}
	}
}
