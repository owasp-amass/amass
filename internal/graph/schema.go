// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// CatalogTypes returns every asset type in the catalog.
func CatalogTypes(catalog []RelationshipSchema, selectors []AssetSearchSchema) map[string]bool {
	types := map[string]bool{}
	for _, s := range selectors {
		types[s.Type] = true
	}
	for _, r := range catalog {
		types[r.SourceType], types[r.DestinationType] = true, true
	}

	return types
}

// RelationshipSchema represents one permitted directed OAM relationship.
type RelationshipSchema struct {
	SourceType      string `json:"source_type"`
	Label           string `json:"label"`
	RelationType    string `json:"relation_type"`
	DestinationType string `json:"destination_type"`
}

// SchemaCatalog exposes authoritative OAM relationship metadata.
type SchemaCatalog interface {
	Relations() []RelationshipSchema
}

func DecodeStrict(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}

	return nil
}
