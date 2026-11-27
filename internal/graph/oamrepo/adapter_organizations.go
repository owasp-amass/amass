// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// LookupOrganizations performs bounded, typed lookups with a conservative
// punctuation fallback. It never scans the repository, and never silently
// selects among multiple plausible legal entities.
func (a Adapter) LookupOrganizations(ctx context.Context, name string, limit int) ([]graph.Asset, error) {
	if a.Repo == nil {
		return nil, errors.New("missing OAM repository")
	}

	name = strings.Join(strings.Fields(name), " ")
	if name == "" || len(name) > 256 || limit < 1 || limit > 10 {
		return nil, errors.New("invalid organization lookup parameters")
	}

	// Models sometimes remove a final period from a company name (e.g.,
	// "Inc." -> "Inc") or change its case. Try those exact forms using
	// indexed content queries. This is intentionally not fuzzy matching:
	// other punctuation and arbitrary string similarity are not accepted as
	// an entity identity.
	variants := organizationNameVariants(name)
	out := make([]graph.Asset, 0, limit)
	seen := make(map[string]bool, limit)
	for _, candidate := range variants {
		if candidate == "" || len(out) >= limit {
			break
		}

		remaining := limit - len(out)
		entities, err := a.Repo.FindEntitiesByContent(ctx, oam.Organization,
			time.Time{}, remaining, dbt.ContentFilters{"name": candidate})
		if err != nil {
			// PostgreSQL reports an empty content query as a sentinel error.
			// Other repository failures must never be mistaken for no matches.
			if strings.TrimSpace(err.Error()) == "zero entities found" {
				continue
			}

			return nil, err
		}
		if len(entities) > remaining {
			return nil, errors.New("repository exceeded organization lookup limit")
		}
		for _, entity := range entities {
			asset, err := convert(entity)
			if err != nil {
				return nil, err
			}
			if !seen[asset.ID] {
				seen[asset.ID] = true
				out = append(out, asset)
			}
		}
	}

	return out, nil
}

// organizationNameVariants returns the exact name forms tried for an
// organization lookup: the name as given, upper case and title case (as
// registries and GLEIF often store names) and lower case (as Amass stores
// the names it collects), each with and without a final period. No other
// normalization or similarity is applied.
func organizationNameVariants(name string) []string {
	name = strings.Join(strings.Fields(name), " ")
	if name == "" {
		return nil
	}

	words := strings.Fields(strings.ToLower(name))
	for i, w := range words {
		r := []rune(w)
		words[i] = strings.ToUpper(string(r[0])) + string(r[1:])
	}

	seen := map[string]bool{}
	var out []string
	for _, form := range []string{name, strings.ToLower(name), strings.ToUpper(name), strings.Join(words, " ")} {
		alt := form + "."
		if strings.HasSuffix(form, ".") {
			alt = strings.TrimSuffix(form, ".")
		}
		for _, v := range []string{form, alt} {
			if v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}

	return out
}

// ResolveOrganizations generates field-specific candidate matches using only
// bounded repository content filters. Alias metadata must be explicitly supplied
// from a curated source; neither aliases nor names imply legal ownership.
func (a Adapter) ResolveOrganizations(ctx context.Context, query graph.OrganizationQuery, limit int) (graph.OrganizationResolution, error) {
	result := graph.OrganizationResolution{
		Query:      query,
		Candidates: []graph.OrganizationCandidate{},
		Status:     "not_found",
	}
	if a.Repo == nil {
		return result, errors.New("missing OAM repository")
	}
	if err := query.Validate(); err != nil {
		return result, err
	}
	if limit < 1 || limit > 10 {
		return result, errors.New("candidate limit must be 1..10")
	}

	// Exact database lookup only. A second bounded query permits a
	// terminal-period variant, which models frequently omit. Fuzzy
	// similarity, suffix removal and unrestricted table scans are prohibited.
	variants := organizationNameVariants
	matches := map[string]*graph.OrganizationCandidate{}
	tooMany := false
	add := func(ent *dbt.Entity, field, value, source string) error {
		asset, err := convert(ent)
		if err != nil {
			return err
		}

		// Make jurisdiction a strict identity constraint if supplied.
		var org oamorg.Organization
		raw, err := json.Marshal(asset.Content)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &org); err != nil {
			return err
		}
		if query.Jurisdiction != "" && org.Jurisdiction != query.Jurisdiction {
			return nil
		}

		c, exists := matches[asset.ID]
		if !exists {
			if len(matches) >= limit {
				tooMany = true
				return nil
			}

			c = &graph.OrganizationCandidate{Asset: asset, Matches: []graph.ResolutionMatch{}}
			matches[asset.ID] = c
		}
		for _, m := range c.Matches {
			if m.Field == field && m.Value == value && m.Source == source {
				return nil
			}
		}

		c.Matches = append(c.Matches, graph.ResolutionMatch{Field: field, Value: value, Source: source})
		return nil
	}
	queryBy := func(field, value, source string) error {
		filters := dbt.ContentFilters{field: value}
		if field == "registration_id" {
			filters["jurisdiction"] = query.Jurisdiction
		}

		// Each lookup requests one extra candidate for truncation detection.
		// Any overflow prevents automatic selection.
		rows, err := a.Repo.FindEntitiesByContent(ctx, oam.Organization, time.Time{}, limit+1, filters)
		if err != nil {
			if strings.TrimSpace(err.Error()) == "zero entities found" {
				return nil
			}

			return err
		}
		if len(rows) > limit {
			tooMany = true
		}
		for _, ent := range rows {
			if err := add(ent, field, value, source); err != nil {
				return err
			}
		}

		return nil
	}
	switch {
	case query.UniqueID != "":
		if err := queryBy("unique_id", query.UniqueID, ""); err != nil {
			return result, err
		}
	case query.RegistrationID != "":
		if err := queryBy("registration_id", query.RegistrationID, ""); err != nil {
			return result, err
		}
	case query.LegalName != "":
		for _, v := range variants(query.LegalName) {
			if err := queryBy("legal_name", v, ""); err != nil {
				return result, err
			}
		}
	case query.Name != "":
		for _, v := range variants(query.Name) {
			for _, field := range []string{"name", "legal_name"} {
				if err := queryBy(field, v, ""); err != nil {
					return result, err
				}
			}
			// another name the organization is known by, such as the one a
			// merge kept when it showed a more complete name
			if err := a.queryByNameClaim(ctx, v, limit, add); err != nil {
				return result, err
			}
		}
		// Resolve explicitly documented trade or historic aliases only.
		// Alias rows point to an existing OAM unique_id; their source is
		// returned in the candidate provenance. No alias is auto-created.
		for _, alias := range a.Aliases {
			if graph.NormalizeOrganizationAlias(alias.Alias) != graph.NormalizeOrganizationAlias(query.Name) {
				continue
			}
			if query.Jurisdiction != "" && alias.Jurisdiction != "" && alias.Jurisdiction != query.Jurisdiction {
				continue
			}
			if err := queryByAlias(alias, add, ctx, a.Repo, limit); err != nil {
				return result, err
			}
		}
	}
	for _, candidate := range matches {
		result.Candidates = append(result.Candidates, *candidate)
	}

	sort.Slice(result.Candidates,
		func(i, j int) bool { return result.Candidates[i].Asset.ID < result.Candidates[j].Asset.ID })
	for i := range result.Candidates {
		sort.Slice(result.Candidates[i].Matches, func(j, k int) bool {
			a, b := result.Candidates[i].Matches[j], result.Candidates[i].Matches[k]
			if a.Field != b.Field {
				return a.Field < b.Field
			}
			if a.Value != b.Value {
				return a.Value < b.Value
			}

			return a.Source < b.Source
		})
	}
	switch {
	case tooMany:
		result.Status = "truncated"
		result.Truncated = true
	case len(result.Candidates) == 0:
		result.Status = "not_found"
	case len(result.Candidates) == 1:
		result.Status = "matched"
	default:
		result.Status = "ambiguous"
	}

	return result, nil
}

// Alias-specific lookup retains the actual curated source rather than
// mislabeling an alias as a database-exact name match.
// queryByNameClaim adds the organizations claiming the exact name as a name
// claim (Organization --id--> Identifier of the org_name or legal_name type).
func (a Adapter) queryByNameClaim(ctx context.Context, name string, limit int,
	add func(*dbt.Entity, string, string, string) error) error {
	for _, idType := range []string{general.OrganizationName, general.LegalName} {
		idents, err := a.Repo.FindEntitiesByContent(ctx, oam.Identifier, time.Time{}, 1,
			dbt.ContentFilters{"unique_id": idType + ":" + name})
		if err != nil || len(idents) == 0 {
			continue
		}
		edges, err := a.Repo.IncomingEdges(ctx, idents[0], time.Time{}, "id")
		if err != nil {
			continue
		}
		for i, e := range edges {
			if i > limit {
				break
			}
			ent, err := a.Repo.FindEntityById(ctx, e.FromEntity.ID)
			if err != nil || ent == nil {
				continue
			}
			if _, ok := ent.Asset.(*oamorg.Organization); !ok {
				continue
			}
			if err := add(ent, idType, name, ""); err != nil {
				return err
			}
		}
	}
	return nil
}

func queryByAlias(alias graph.OrganizationAlias,
	add func(*dbt.Entity, string, string, string) error, ctx context.Context,
	repo repository.Repository, limit int) error {
	rows, err := repo.FindEntitiesByContent(ctx, oam.Organization, time.Time{}, limit+1,
		dbt.ContentFilters{"unique_id": alias.UniqueID})
	if err != nil {
		if strings.TrimSpace(err.Error()) == "zero entities found" {
			return nil
		}

		return err
	}
	for _, ent := range rows {
		// An alias jurisdiction must agree with the actual OAM entity.
		if alias.Jurisdiction != "" {
			org, ok := ent.Asset.(*oamorg.Organization)
			if !ok {
				return errors.New("alias target is not an Organization")
			}
			if org.Jurisdiction != alias.Jurisdiction {
				continue
			}
		}
		if err := add(ent, "alias", alias.Alias, alias.Source); err != nil {
			return err
		}
	}

	return nil
}

// ResolveAsset requires a registered typed selector, uses only bounded read
// APIs, and never silently resolves an ambiguous query to its first result.
func (a Adapter) ResolveAsset(ctx context.Context, selector graph.AssetSelector, limit int) (graph.AssetResolution, error) {
	result := graph.AssetResolution{Query: selector, Status: "not_found", Candidates: []graph.OrganizationCandidate{}}
	if a.Repo == nil {
		return result, errors.New("missing OAM repository")
	}
	if err := selector.Validate((Catalog{}).SearchFields()); err != nil {
		return result, err
	}
	if limit < 1 || limit > 10 {
		return result, errors.New("asset resolution limit must be 1..10")
	}
	if selector.EntityID != "" {
		asset, err := a.GetAsset(ctx, selector.EntityID)
		if err != nil {
			// Invalid or inaccessible IDs are errors, not negative evidence.
			return result, fmt.Errorf("resolve entity_id: %w", err)
		}
		if asset.Type != selector.Type {
			return result, errors.New("entity_id does not match asserted OAM type")
		}

		result.Candidates = append(result.Candidates, graph.OrganizationCandidate{
			Asset: asset, Matches: []graph.ResolutionMatch{{Field: "entity_id", Value: selector.EntityID}},
		})
		result.Status = "matched"
		return result, nil
	}

	value := selector.Value
	if selector.Type == "FQDN" && selector.Field == "name" {
		value = strings.ToLower(strings.TrimSuffix(value, "."))
	}

	// The repository uses a bounded indexed query. Ask for one extra record
	// so a capped result can never masquerade as a unique result.
	filter := dbt.ContentFilters{selector.Field: value}
	rows, err := a.Repo.FindEntitiesByContent(ctx, oam.AssetType(selector.Type), time.Time{}, limit+1, filter)
	if err != nil {
		if strings.TrimSpace(err.Error()) == "zero entities found" {
			return result, nil
		}

		return result, err
	}
	if len(rows) > limit {
		result.Truncated = true
	}
	for _, ent := range rows {
		if len(result.Candidates) >= limit {
			break
		}

		asset, err := convert(ent)
		if err != nil {
			return result, err
		}
		if asset.Type != selector.Type {
			return result, errors.New("repository returned wrong OAM type")
		}

		result.Candidates = append(result.Candidates, graph.OrganizationCandidate{
			Asset: asset, Matches: []graph.ResolutionMatch{{Field: selector.Field, Value: value}},
		})
	}

	sort.Slice(result.Candidates,
		func(i, j int) bool { return result.Candidates[i].Asset.ID < result.Candidates[j].Asset.ID })
	switch {
	case result.Truncated:
		result.Status = "truncated"
	case len(result.Candidates) == 0:
		result.Status = "not_found"
	case len(result.Candidates) == 1:
		result.Status = "matched"
	default:
		result.Status = "ambiguous"
	}

	return result, nil
}
