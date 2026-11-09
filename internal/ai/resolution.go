// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// OrganizationQuery contains one asserted identifier and an optional
// jurisdiction qualifier. The planner must never invent these values.
type OrganizationQuery struct {
	Name           string `json:"name,omitempty"`
	LegalName      string `json:"legal_name,omitempty"`
	UniqueID       string `json:"unique_id,omitempty"`
	RegistrationID string `json:"registration_id,omitempty"`
	Jurisdiction   string `json:"jurisdiction,omitempty"`
}
type OrganizationAlias struct {
	Alias        string `json:"alias"`
	UniqueID     string `json:"unique_id"`
	Source       string `json:"source"`
	Jurisdiction string `json:"jurisdiction,omitempty"`
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

// Only whitespace, case, and a final full stop are normalized for curated
// aliases. Arbitrary edit distance and corporate suffix removal are unsafe.
func NormalizeOrganizationAlias(s string) string {
	s = strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(s)), " "))
	return strings.TrimSuffix(s, ".")
}
func LoadOrganizationAliases(r io.Reader) ([]OrganizationAlias, error) {
	const maxBytes = 1024 * 1024
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBytes {
		return nil, errors.New("organization aliases file exceeds 1 MiB")
	}
	var doc struct {
		Aliases []OrganizationAlias `json:"aliases"`
	}
	if err := decodeStrict(b, &doc); err != nil {
		return nil, fmt.Errorf("decode aliases: %w", err)
	}
	if len(doc.Aliases) > 1000 {
		return nil, errors.New("organization aliases exceed 1000 entries")
	}
	for i, a := range doc.Aliases {
		if NormalizeOrganizationAlias(a.Alias) == "" || len(a.Alias) > 256 ||
			strings.TrimSpace(a.UniqueID) == "" || len(a.UniqueID) > 256 ||
			strings.TrimSpace(a.Source) == "" || len(a.Source) > 512 || len(a.Jurisdiction) > 64 {
			return nil, fmt.Errorf("invalid alias at index %d: alias, unique_id and source are required", i)
		}
	}
	return doc.Aliases, nil
}
