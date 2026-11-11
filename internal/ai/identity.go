// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/biter777/countries"
)

//go:embed semantics/identity_checks.json
var identityChecksJSON []byte

type identityChecks struct {
	License           string   `json:"_license"`
	About             string   `json:"_about"`
	EnrichmentSources []string `json:"enrichment_sources"`
	IdentityIDTypes   []string `json:"identity_id_types"`
	IdentityLabels    []string `json:"identity_labels"`
	LegalFields       []string `json:"legal_fields"`
}

var loadIdentityChecks = sync.OnceValue(func() identityChecks {
	var c identityChecks
	if err := decodeStrict(identityChecksJSON, &c); err != nil {
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
	graph  Graph
	report IdentityReport
}

func (s *identitySearch) edges(id, dir, label string) ([]Relation, error) {
	if s.report.Reads >= dupMaxReads {
		return nil, errDupReadLimit
	}

	s.report.Reads++
	if b, ok := s.graph.(BoundedGraph); ok {
		edges, _, err := b.EdgesLimited(s.ctx, id, dir, label, time.Time{}, MaxEdgeRead)
		return edges, err
	}

	return s.graph.Edges(s.ctx, id, dir, label, time.Time{})
}

func (s *identitySearch) asset(id string) (Asset, error) {
	if s.report.Reads >= dupMaxReads {
		return Asset{}, errDupReadLimit
	}

	s.report.Reads++
	return s.graph.GetAsset(s.ctx, id)
}

// sources returns the source names recorded on an edge.
func (s *identitySearch) sources(edgeID string) ([]string, error) {
	r, ok := s.graph.(EdgeEvidenceReader)
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
		if !slices.ContainsFunc(loadIdentityChecks().EnrichmentSources, func(e string) bool {
			return strings.EqualFold(e, src)
		}) {
			return false
		}
	}

	return true
}

func anyEnrichment(sources []string) bool {
	for _, src := range sources {
		if slices.ContainsFunc(loadIdentityChecks().EnrichmentSources, func(e string) bool {
			return strings.EqualFold(e, src)
		}) {
			return true
		}
	}

	return false
}

// FindIdentityConflicts checks every organization with a legal identity
// against the names and countries other sources recorded for it.
func FindIdentityConflicts(ctx context.Context, graph Graph) (IdentityReport, error) {
	s := &identitySearch{ctx: ctx, graph: graph}
	orgs, err := graph.FindAssets(ctx, "Organization", time.Time{}, dupMaxOrganizations+1)
	if err != nil {
		return s.report, err
	}
	if len(orgs) > dupMaxOrganizations {
		orgs = orgs[:dupMaxOrganizations]
		s.report.Truncated, s.report.Reason = true, fmt.Sprintf("more than %d organizations", dupMaxOrganizations)
	}

	for _, o := range orgs {
		legal := contentString(o, "legal_name")
		juris := strings.ToUpper(strings.TrimSpace(contentString(o, "jurisdiction")))
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
func (s *identitySearch) check(o Asset, legal, juris string) (*IdentityConflict, error) {
	checks := loadIdentityChecks()
	var independent []string
	var enrichEdges []string

	ids, err := s.edges(o.ID, "out", "id")
	if err != nil {
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

		idtype := strings.ToLower(contentString(a, "id_type"))
		value := contentString(a, "id")
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

	return &IdentityConflict{ID: IdentityConflictID(o.ID, legal, juris), Organization: AssetLabel(o), OrgID: o.ID,
		LegalName: legal, Jurisdiction: juris, Reasons: reasons, EdgeIDs: enrichEdges,
		Fields: append([]string(nil), checks.LegalFields...), CreatedAt: time.Now().UTC()}, nil
}

// contactCountries returns the countries of the organization's contact
// records' locations.
func (s *identitySearch) contactCountries(o Asset) (map[string]bool, error) {
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
		for _, l := range locs {
			a, err := s.asset(l.ToID)
			if err != nil {
				return nil, err
			}
			if c := countryCode(contentString(a, "country")); c != "" {
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

// IdentityRecord is everything a correction changed, so it can be undone.
type IdentityRecord struct {
	OrgID string `json:"org_id"`
	// Before is the organization's content before the correction.
	Before json.RawMessage `json:"before"`
	// Edges are the relationships the correction touched: deleted when
	// only enrichment sources recorded them, otherwise only those sources'
	// tags were removed.
	Edges []CorrectedEdge `json:"edges"`
}

// CorrectedEdge is one relationship a correction removed or untagged.
type CorrectedEdge struct {
	MergedEdge
	Deleted     bool        `json:"deleted"`
	RemovedTags []MergedTag `json:"removed_tags,omitempty"`
}

// IdentityCorrector applies and undoes identity corrections.
type IdentityCorrector interface {
	CorrectIdentity(ctx context.Context, c IdentityConflict) (IdentityRecord, error)
	UndoIdentityCorrection(ctx context.Context, rec IdentityRecord) error
}

// IdentityOutcome records a decision on an identity correction.
type IdentityOutcome struct {
	ProposalID string          `json:"proposal_id"`
	Status     string          `json:"status"`
	Reviewer   string          `json:"reviewer"`
	Record     *IdentityRecord `json:"record,omitempty"`
	At         time.Time       `json:"at"`
}

// IdentityEntry is an identity correction proposal with its latest outcome.
type IdentityEntry struct {
	Proposal IdentityConflict `json:"proposal"`
	Status   string           `json:"status"`
	Outcome  *IdentityOutcome `json:"outcome,omitempty"`
}

// SubmitIdentityConflicts records conflicts not already in the journal.
func (j *Journal) SubmitIdentityConflicts(conflicts []IdentityConflict) ([]IdentityConflict, error) {
	state, err := j.IdentityState()
	if err != nil {
		return nil, err
	}

	var added []IdentityConflict
	for _, c := range conflicts {
		if c.ID == "" || c.OrgID == "" {
			return added, errors.New("identity correction needs an ID and an organization")
		}
		if _, ok := state[c.ID]; ok {
			continue
		}
		if err := j.append("identity_proposal", c); err != nil {
			return added, err
		}

		added = append(added, c)
	}

	return added, nil
}

// RecordIdentity records a decision on an identity correction.
func (j *Journal) RecordIdentity(o IdentityOutcome) error {
	if o.ProposalID == "" || o.Reviewer == "" {
		return errors.New("proposal ID and reviewer required")
	}
	switch o.Status {
	case ProposalRejected, ProposalRetracted:
	case ProposalApplied:
		if o.Record == nil {
			return errors.New("an applied correction records what it changed")
		}
	default:
		return fmt.Errorf("invalid identity status %q", o.Status)
	}

	o.At = time.Now().UTC()
	return j.append("identity_outcome", o)
}

// IdentityState replays the journal into each identity correction's
// current status. A missing journal is empty.
func (j *Journal) IdentityState() (map[string]*IdentityEntry, error) {
	state := map[string]*IdentityEntry{}
	lines, err := j.History()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state, nil
		}

		return nil, err
	}
	for _, line := range lines {
		var rec struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, err
		}
		switch rec.Kind {
		case "identity_proposal":
			var c IdentityConflict
			if err := json.Unmarshal(rec.Data, &c); err != nil {
				return nil, err
			}
			if _, ok := state[c.ID]; !ok {
				state[c.ID] = &IdentityEntry{Proposal: c, Status: ProposalPending}
			}
		case "identity_outcome":
			var o IdentityOutcome
			if err := json.Unmarshal(rec.Data, &o); err != nil {
				return nil, err
			}
			if e, ok := state[o.ProposalID]; ok {
				e.Status, e.Outcome = o.Status, &o
			}
		}
	}

	return state, nil
}

// IdentityEntries lists the journal's identity corrections, pending first.
func (j *Journal) IdentityEntries() ([]IdentityEntry, error) {
	state, err := j.IdentityState()
	if err != nil {
		return nil, err
	}

	out := make([]IdentityEntry, 0, len(state))
	for _, e := range state {
		out = append(out, *e)
	}
	sort.Slice(out, func(a, b int) bool {
		pa, pb := out[a].Status == ProposalPending, out[b].Status == ProposalPending
		if pa != pb {
			return pa
		}
		return out[a].Proposal.Organization < out[b].Proposal.Organization
	})
	return out, nil
}

// FormatIdentityEntries renders identity corrections for review.
func FormatIdentityEntries(entries []IdentityEntry) string {
	if len(entries) == 0 {
		return "No identity corrections in the journal.\n"
	}

	var b strings.Builder
	for i, e := range entries {
		if i > 0 {
			b.WriteString("\n")
		}

		p := e.Proposal
		fmt.Fprintf(&b, "%s  %s\n", p.ID, strings.ToUpper(e.Status))
		fmt.Fprintf(&b, "  %s [%s]: remove legal identity %q (%s), %d relationship(s) only %s recorded\n",
			p.Organization, p.OrgID, p.LegalName, p.Jurisdiction, len(p.EdgeIDs),
			strings.Join(loadIdentityChecks().EnrichmentSources, ", "))
		for _, r := range p.Reasons {
			fmt.Fprintf(&b, "  - %s\n", r)
		}
		if o := e.Outcome; o != nil {
			fmt.Fprintf(&b, "  %s by %s at %s\n", o.Status, o.Reviewer, o.At.Format(time.RFC3339))
		}
	}

	return b.String()
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

// ApplyIdentityCorrection corrects a pending proposal's organization and
// records what changed.
func ApplyIdentityCorrection(ctx context.Context, c IdentityCorrector, j *Journal, p IdentityConflict,
	reviewer string) (IdentityRecord, error) {
	rec, err := c.CorrectIdentity(ctx, p)
	if err != nil {
		return rec, fmt.Errorf("correct %s [%s]: %w", p.Organization, p.OrgID, err)
	}
	if err := j.RecordIdentity(IdentityOutcome{ProposalID: p.ID, Status: ProposalApplied, Reviewer: reviewer,
		Record: &rec}); err != nil {
		return rec, fmt.Errorf("%s was corrected but the journal was not updated: %w", p.Organization, err)
	}

	return rec, nil
}
