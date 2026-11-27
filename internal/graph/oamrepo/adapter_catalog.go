// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"sort"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	oam "github.com/owasp-amass/open-asset-model"
)

// Catalog derives permitted graph transitions from the OAM package.
type Catalog struct{}

// Relations enumerates actual OAM labels and relation types. Sorted so
// different providers and runs receive the same schema context.
func (Catalog) Relations() []graph.RelationshipSchema {
	var results []graph.RelationshipSchema
	for _, src := range oam.AssetList {
		for _, label := range oam.GetAssetOutgoingRelations(src) {
			for _, relType := range oam.RelationList {
				for _, dst := range oam.GetTransformAssetTypes(src, label, relType) {
					results = append(results, graph.RelationshipSchema{
						SourceType: string(src), Label: label,
						RelationType: string(relType), DestinationType: string(dst),
					})
				}
			}
		}
	}

	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.SourceType != b.SourceType {
			return a.SourceType < b.SourceType
		}
		if a.Label != b.Label {
			return a.Label < b.Label
		}
		if a.RelationType != b.RelationType {
			return a.RelationType < b.RelationType
		}

		return a.DestinationType < b.DestinationType
	})
	return results
}

var (
	semanticsOnce  sync.Once
	semanticsTable *semantics.Table
)

// Attribution returns what an OAM relationship says about who controls its
// source asset, from internal/semantics. The embedded table is validated
// in CI against the OAM taxonomy; an unknown relationship never attributes
// ownership.
func (Catalog) Attribution(source, label, relationType, destination string) (string, bool) {
	semanticsOnce.Do(func() { semanticsTable, _ = semantics.Load() })
	if semanticsTable == nil {
		return "", false
	}

	r, ok := semanticsTable.Lookup(source, label, relationType, destination)
	return r.Attribution, ok
}

// Meaning returns the full semantics table entry of an OAM relationship.
func (Catalog) Meaning(source, label, relationType, destination string) (graph.RelationMeaning, bool) {
	semanticsOnce.Do(func() { semanticsTable, _ = semantics.Load() })
	if semanticsTable == nil {
		return graph.RelationMeaning{}, false
	}

	r, ok := semanticsTable.Lookup(source, label, relationType, destination)
	return graph.RelationMeaning{Attribution: r.Attribution, Purpose: r.Purpose, Vendor: !r.NotVendor}, ok
}

// SearchFields enumerates indexed typed selectors for each OAM asset kind.
// These keys follow the Asset Database content-filter registries.
// ContactRecord currently has only discovered_at, a non-identity timestamp:
// use an explicit entity_id for reliable lookup.
func (Catalog) SearchFields() []graph.AssetSearchSchema {
	filters := map[string][]string{
		"Account":          {"unique_id", "account_type", "username", "account_number"},
		"AutnumRecord":     {"number", "handle", "name", "whois_server"},
		"AutonomousSystem": {"number"},
		"ContactRecord":    {},
		"DomainRecord":     {"domain", "name", "extension", "punycode", "id", "whois_server"},
		"File":             {"url", "name", "type"},
		"FQDN":             {"name"},
		"FundsTransfer":    {"unique_id", "amount", "reference_number"},
		"Identifier":       {"unique_id", "id", "id_type"},
		"IPAddress":        {"address"},
		"IPNetRecord":      {"cidr", "handle", "name", "start_address", "end_address", "whois_server", "parent_handle"},
		"StreetAddress": {
			"address",
			"building",
			"building_number",
			"province",
			"street_name",
			"unit",
			"locality",
			"city",
			"country",
			"postal_code",
		},
		"GeoLocation":    {"unique_id", "latitude", "longitude"},
		"Netblock":       {"cidr"},
		"Organization":   {"unique_id", "name", "legal_name", "registration_id", "jurisdiction"},
		"Person":         {"unique_id", "full_name", "first_name", "family_name"},
		"Phone":          {"e164", "country_code"},
		"Product":        {"unique_id", "product_name", "product_type"},
		"ProductRelease": {"name"},
		"Service":        {"unique_id", "service_type"},
		"StorageBucket":  {"unique_id", "bucket_name", "provider", "service"},
		"TLSCertificate": {"serial_number", "subject_common_name"},
		"URL":            {"url", "scheme"},
	}
	out := make([]graph.AssetSearchSchema, 0, len(oam.AssetList))
	for _, t := range oam.AssetList {
		fields, ok := filters[string(t)]
		if !ok {
			continue
		}

		out = append(out, graph.AssetSearchSchema{Type: string(t), Fields: fields})
	}

	return out
}
