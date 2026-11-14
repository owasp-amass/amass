// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/ai/graph"
)

type OrganizationAlias struct {
	Alias        string `json:"alias"`
	UniqueID     string `json:"unique_id"`
	Source       string `json:"source"`
	Jurisdiction string `json:"jurisdiction,omitempty"`
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
	if err := graph.DecodeStrict(b, &doc); err != nil {
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
