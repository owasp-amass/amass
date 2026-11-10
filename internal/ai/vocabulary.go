// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// The user-language vocabulary lives in data next to the relationship
// semantics table, so synonyms for new or existing OAM types, labels and
// selector fields are added without code changes. It is an interpretation
// aid, not an OAM schema extension: only names registered by the active
// OAM catalog are ever used, and "addresses" stays ambiguous between
// network and physical addresses.
//
//go:embed semantics/vocabulary.json
var vocabularyJSON []byte

type vocabulary struct {
	AssetTypes   map[string][]string `json:"asset_types"`
	Relations    map[string][]string `json:"relations"`
	SearchFields map[string][]string `json:"search_fields"`
	Operations   map[string][]string `json:"operations"`
}

var (
	intentVocabulary                 map[string][]string
	relationVocabulary               map[string][]string
	searchableFieldVocabulary        map[string][]string
	investigationOperationVocabulary map[string][]string
)

func init() {
	v, err := parseVocabulary(vocabularyJSON)
	if err != nil {
		panic(err)
	}

	intentVocabulary, relationVocabulary = v.AssetTypes, v.Relations
	searchableFieldVocabulary, investigationOperationVocabulary = v.SearchFields, v.Operations
}

// parseVocabulary decodes the vocabulary, ignoring "_" documentation keys
// and rejecting empty sections or entries.
func parseVocabulary(data []byte) (vocabulary, error) {
	var v vocabulary
	if err := json.Unmarshal(data, &v); err != nil {
		return v, fmt.Errorf("parse AI vocabulary: %w", err)
	}
	for name, section := range map[string]map[string][]string{"asset_types": v.AssetTypes,
		"relations": v.Relations, "search_fields": v.SearchFields, "operations": v.Operations} {
		if len(section) == 0 {
			return v, fmt.Errorf("AI vocabulary section %s is empty", name)
		}
		for key, words := range section {
			if key == "" || len(words) == 0 {
				return v, fmt.Errorf("AI vocabulary %s entry %q has no words", name, key)
			}
		}
	}

	return v, nil
}
