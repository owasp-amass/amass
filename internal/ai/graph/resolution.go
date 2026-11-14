// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
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

type AssetResolution struct {
	Query      AssetSelector           `json:"query"`
	Status     string                  `json:"status"`
	Candidates []OrganizationCandidate `json:"candidates"`
	Truncated  bool                    `json:"truncated"`
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

// OrganizationQuery contains one asserted identifier and an optional
// jurisdiction qualifier. The planner must never invent these values.
type OrganizationQuery struct {
	Name           string `json:"name,omitempty"`
	LegalName      string `json:"legal_name,omitempty"`
	UniqueID       string `json:"unique_id,omitempty"`
	RegistrationID string `json:"registration_id,omitempty"`
	Jurisdiction   string `json:"jurisdiction,omitempty"`
}

type ResolutionMatch struct {
	Field  string `json:"field"`
	Value  string `json:"value"`
	Source string `json:"source,omitempty"`
}

type OrganizationCandidate struct {
	Asset   Asset             `json:"asset"`
	Matches []ResolutionMatch `json:"matches"`
}

type OrganizationResolution struct {
	Query      OrganizationQuery       `json:"query"`
	Status     string                  `json:"status"`
	Candidates []OrganizationCandidate `json:"candidates"`
	Truncated  bool                    `json:"truncated"`
}

func (q OrganizationQuery) Validate() error {
	identifiers := []string{q.Name, q.LegalName, q.UniqueID, q.RegistrationID}
	count := 0
	for _, v := range identifiers {
		if v != "" {
			count++
		}
		if len(v) > 256 {
			return errors.New("organization identifier exceeds 256 bytes")
		}
	}
	if count != 1 {
		return errors.New("provide exactly one of name, legal_name, unique_id, or registration_id")
	}
	if len(q.Jurisdiction) > 64 {
		return errors.New("jurisdiction exceeds 64 bytes")
	}
	if q.RegistrationID != "" && q.Jurisdiction == "" {
		return errors.New("registration_id requires jurisdiction")
	}

	return nil
}
