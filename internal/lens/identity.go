// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/biter777/countries"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

var identityChecksJSON = semantics.File("identity_checks.json")

type identityChecks struct {
	License           string   `json:"_license"`
	About             string   `json:"_about"`
	EnrichmentSources []string `json:"enrichment_sources"`
	IdentityIDTypes   []string `json:"identity_id_types"`
	IdentityLabels    []string `json:"identity_labels"`
	LegalFields       []string `json:"legal_fields"`
}

var LoadIdentityChecks = sync.OnceValue(func() identityChecks {
	var c identityChecks
	if err := graph.DecodeStrict(identityChecksJSON, &c); err != nil {
		panic("identity_checks.json: " + err.Error())
	}
	if len(c.EnrichmentSources) == 0 || len(c.IdentityIDTypes) == 0 {
		panic("identity_checks.json: enrichment_sources and identity_id_types are required")
	}

	return c
})

// IdentityPrefix starts every identity correction proposal ID.
const IdentityPrefix = "idc-"

// IdentityConflict is an organization whose legal identity, attached by an
// enrichment source, contradicts the organization's own evidence.
type IdentityConflict struct {
	ID           string `json:"id"`
	Organization string `json:"organization"`
	OrgID        string `json:"org_id"`
	LegalName    string `json:"legal_name,omitempty"`
	Jurisdiction string `json:"jurisdiction,omitempty"`
	// Reasons say how the evidence contradicts the identity.
	Reasons []string `json:"reasons"`
	// EdgeIDs are the relationships an enrichment source recorded that a
	// correction removes; Fields the legal fields it clears.
	EdgeIDs   []string  `json:"edge_ids"`
	Fields    []string  `json:"fields"`
	CreatedAt time.Time `json:"created_at"`
}

// IdentityReport is the result of an identity check.
type IdentityReport struct {
	Organizations int                `json:"organizations"`
	Conflicts     []IdentityConflict `json:"conflicts"`
	Reads         int                `json:"reads"`
	Truncated     bool               `json:"truncated"`
	Reason        string             `json:"reason,omitempty"`
}

// IdentityConflictID is a stable identifier for correcting one
// organization's identity.
func IdentityConflictID(orgID, legalName, jurisdiction string) string {
	sum := sha256.Sum256([]byte(orgID + "\x00" + legalName + "\x00" + jurisdiction))
	return IdentityPrefix + hex.EncodeToString(sum[:8])
}

type identitySearch struct {
	ctx    context.Context
	graph  graph.Graph
	report IdentityReport
	batch  batchAssets
}

// spend counts one database read, or reports that the budget is spent.
func (s *identitySearch) spend() bool {
	if s.report.Reads >= dupMaxReads {
		return false
	}
	s.report.Reads++
	return true
}

// edges reads an asset's edges completely within the check's read budget;
// see dupSearch.edges.
func (s *identitySearch) edges(id, dir, label string) ([]graph.Relation, error) {
	if s.report.Reads >= dupMaxReads {
		return nil, errDupReadLimit
	}

	spend := func() bool {
		if s.report.Reads >= dupMaxReads {
			return false
		}
		s.report.Reads++
		return true
	}
	edges, more, err := graph.ReadEdges(s.ctx, s.graph, id, dir, label, LensMaxPerLabel, spend)
	if err == nil && more && !s.report.Truncated {
		s.report.Truncated, s.report.Reason = true, partialRead(s.report.Reads >= dupMaxReads, id, dir, label)
	}

	return edges, err
}

func (s *identitySearch) asset(id string) (graph.Asset, error) {
	if a, ok := s.batch.get(id); ok {
		return a, nil
	}
	if s.report.Reads >= dupMaxReads {
		return graph.Asset{}, errDupReadLimit
	}

	s.report.Reads++
	return s.graph.GetAsset(s.ctx, id)
}

// sources returns the source names recorded on an edge.
func (s *identitySearch) sources(edgeID string) ([]string, error) {
	r, ok := s.graph.(graph.EdgeEvidenceReader)
	if !ok {
		return nil, errors.New("the graph cannot read relationship sources")
	}
	if s.report.Reads >= dupMaxReads {
		return nil, errDupReadLimit
	}

	s.report.Reads++
	ev, err := r.EdgeEvidence(s.ctx, edgeID, 100)
	if err != nil {
		return nil, err
	}

	var out []string
	for _, e := range ev {
		if e.SourceID != "" && !slices.Contains(out, e.SourceID) {
			out = append(out, e.SourceID)
		}
	}

	return out, nil
}

// onlyEnrichment reports whether every source of a relationship is an
// enrichment source.
func onlyEnrichment(sources []string) bool {
	if len(sources) == 0 {
		return false
	}
	for _, src := range sources {
		if !slices.ContainsFunc(LoadIdentityChecks().EnrichmentSources, func(e string) bool {
			return strings.EqualFold(e, src)
		}) {
			return false
		}
	}

	return true
}

func anyEnrichment(sources []string) bool {
	for _, src := range sources {
		if slices.ContainsFunc(LoadIdentityChecks().EnrichmentSources, func(e string) bool {
			return strings.EqualFold(e, src)
		}) {
			return true
		}
	}

	return false
}

// FindIdentityConflicts checks every organization with a legal identity
// against the names and countries other sources recorded for it.
func FindIdentityConflicts(ctx context.Context, g graph.Graph) (IdentityReport, error) {
	s := &identitySearch{ctx: ctx, graph: g}
	orgs, err := g.FindAssets(ctx, "Organization", time.Time{}, dupMaxOrganizations+1)
	if err != nil {
		return s.report, err
	}
	if len(orgs) > dupMaxOrganizations {
		orgs = orgs[:dupMaxOrganizations]
		s.report.Truncated, s.report.Reason = true, fmt.Sprintf("more than %d organizations", dupMaxOrganizations)
	}

	for _, o := range orgs {
		legal := graph.ContentString(o, "legal_name")
		juris := strings.ToUpper(strings.TrimSpace(graph.ContentString(o, "jurisdiction")))
		if legal == "" && juris == "" {
			continue
		}

		s.report.Organizations++
		c, err := s.check(o, legal, juris)
		if errors.Is(err, errDupReadLimit) {
			s.report.Truncated, s.report.Reason = true, err.Error()
			break
		} else if err != nil {
			return s.report, err
		}
		if c != nil {
			s.report.Conflicts = append(s.report.Conflicts, *c)
		}
	}

	sort.Slice(s.report.Conflicts, func(i, j int) bool {
		return s.report.Conflicts[i].Organization < s.report.Conflicts[j].Organization
	})
	return s.report, nil
}

// check compares one organization's legal identity with its evidence.
func (s *identitySearch) check(o graph.Asset, legal, juris string) (*IdentityConflict, error) {
	checks := LoadIdentityChecks()
	var independent []string
	var enrichEdges []string

	ids, err := s.edges(o.ID, "out", "id")
	if err != nil {
		return nil, err
	}
	if err := s.batch.load(s.ctx, s.graph, ids, "out", s.spend); err != nil {
		return nil, err
	}
	for _, e := range ids {
		a, err := s.asset(e.ToID)
		if err != nil {
			return nil, err
		}

		srcs, err := s.sources(e.ID)
		if err != nil {
			return nil, err
		}

		idtype := strings.ToLower(graph.ContentString(a, "id_type"))
		value := graph.ContentString(a, "id")
		if (idtype == "org_name" || idtype == "legal_name") && !onlyEnrichment(srcs) && len(srcs) > 0 {
			independent = append(independent, value)
		}
		if slices.Contains(checks.IdentityIDTypes, idtype) && anyEnrichment(srcs) {
			enrichEdges = append(enrichEdges, e.ID)
		}
	}

	for _, label := range checks.IdentityLabels {
		for _, dir := range []string{"out", "in"} {
			if label != "subsidiary" && dir == "in" {
				continue
			}

			rels, err := s.edges(o.ID, dir, label)
			if err != nil {
				return nil, err
			}
			for _, e := range rels {
				srcs, err := s.sources(e.ID)
				if err != nil {
					return nil, err
				}
				if anyEnrichment(srcs) {
					enrichEdges = append(enrichEdges, e.ID)
				}
			}
		}
	}

	countries, err := s.contactCountries(o)
	if err != nil {
		return nil, err
	}

	var reasons []string
	if jc := jurisdictionCountry(juris); jc != "" && len(countries) > 0 && !countries[jc] {
		reasons = append(reasons, fmt.Sprintf("jurisdiction %s, but its contact records are in %s", juris,
			strings.Join(sortedKeys(countries), ", ")))
	}
	if legal != "" && len(independent) > 0 {
		lb := brandName(legal)
		agrees := false
		for _, n := range independent {
			if brandName(n) == lb {
				agrees = true
				break
			}
		}
		if !agrees {
			reasons = append(reasons, fmt.Sprintf("legal name %q matches none of the names other sources gave it (%s)",
				legal, strings.Join(independent, "; ")))
		}
	}
	if len(reasons) == 0 {
		return nil, nil
	}

	return &IdentityConflict{ID: IdentityConflictID(o.ID, legal, juris), Organization: graph.AssetLabel(o), OrgID: o.ID,
		LegalName: legal, Jurisdiction: juris, Reasons: reasons, EdgeIDs: enrichEdges,
		Fields: append([]string(nil), checks.LegalFields...), CreatedAt: time.Now().UTC()}, nil
}

// contactCountries returns the countries of the organization's contact
// records' locations.
func (s *identitySearch) contactCountries(o graph.Asset) (map[string]bool, error) {
	out := map[string]bool{}
	crs, err := s.edges(o.ID, "in", "organization")
	if err != nil {
		return nil, err
	}
	for i, e := range crs {
		if i >= dupMaxContacts {
			break
		}

		locs, err := s.edges(e.FromID, "out", "location")
		if err != nil {
			return nil, err
		}
		if err := s.batch.load(s.ctx, s.graph, locs, "out", s.spend); err != nil {
			return nil, err
		}
		for _, l := range locs {
			a, err := s.asset(l.ToID)
			if err != nil {
				return nil, err
			}
			if c := countryCode(graph.ContentString(a, "country")); c != "" {
				out[c] = true
			}
		}
	}

	return out, nil
}

// jurisdictionCountry is the country of a jurisdiction such as US-DE.
func jurisdictionCountry(j string) string {
	c, _, _ := strings.Cut(j, "-")
	return countryCode(c)
}

// countryCode normalizes a country name or code to ISO 3166 alpha-2.
func countryCode(c string) string {
	c = strings.TrimSpace(c)
	if c == "" {
		return ""
	}
	if code := countries.ByName(c); code.IsValid() {
		return code.Alpha2()
	}

	return ""
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FormatIdentityReport renders an identity check for a terminal.
func FormatIdentityReport(r IdentityReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Checked %d organizations with a legal identity (%d reads).", r.Organizations, r.Reads)
	if r.Truncated {
		fmt.Fprintf(&b, " Incomplete: %s.", r.Reason)
	}
	b.WriteString("\n")
	if len(r.Conflicts) == 0 {
		b.WriteString("No legal identity contradicts its organization's evidence.\n")
		return b.String()
	}

	for _, c := range r.Conflicts {
		fmt.Fprintf(&b, "\n%s [%s]: legal identity %q (%s)\n", c.Organization, c.OrgID, c.LegalName, c.Jurisdiction)
		for _, reason := range c.Reasons {
			fmt.Fprintf(&b, "  - %s\n", reason)
		}
	}

	return b.String()
}

// IsEnrichmentSource reports whether a source looks companies up by name
// in a registry and can attach another company's record.
func IsEnrichmentSource(src string) bool {
	return anyEnrichment([]string{src})
}
