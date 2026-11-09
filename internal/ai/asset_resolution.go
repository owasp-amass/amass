// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
)

// AssetSelector identifies an existing OAM asset using one typed repository
// field, or its explicit graph database entity ID. Never choose a result by
// arbitrary similarity or by the first item of a broad search.
type AssetSelector struct {
	Type     string `json:"type"`
	Field    string `json:"field,omitempty"`
	Value    string `json:"value,omitempty"`
	EntityID string `json:"entity_id,omitempty"`
}
type AssetSearchSchema struct {
	Type   string   `json:"type"`
	Fields []string `json:"fields"`
}
type AssetSearchCatalog interface {
	SearchFields() []AssetSearchSchema
}
type AssetResolution struct {
	Query      AssetSelector           `json:"query"`
	Status     string                  `json:"status"`
	Candidates []OrganizationCandidate `json:"candidates"`
	Truncated  bool                    `json:"truncated"`
}
type AssetResolver interface {
	ResolveAsset(context.Context, AssetSelector, int) (AssetResolution, error)
}

func (s AssetSelector) Validate(catalog []AssetSearchSchema) error {
	if s.Type == "" {
		return errors.New("asset selector type is required")
	}
	if len(s.Value) > 2048 || len(s.EntityID) > 128 {
		return errors.New("asset selector exceeds size policy")
	}
	if s.EntityID != "" {
		if s.Field != "" || s.Value != "" {
			return errors.New("entity_id cannot be combined with field/value")
		}
	} else if s.Field == "" || s.Value == "" {
		return errors.New("asset selector requires field and value, or entity_id")
	}
	for _, a := range catalog {
		if a.Type != s.Type {
			continue
		}
		if s.EntityID != "" {
			return nil
		}
		for _, f := range a.Fields {
			if f == s.Field {
				return nil
			}
		}
		return fmt.Errorf("field %q is not indexed for OAM asset type %s", s.Field, s.Type)
	}
	return fmt.Errorf("unregistered OAM asset type %q", s.Type)
}
