// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/registrant"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// Org-unit correlation links a parent organization to one of its units
// (a university system to a campus, a company to a division) when funding and
// other data are split across separate organization records for the same
// institution. It is a Goal-2 inference: it emits review-gated org_unit
// relationship proposals through the generic relation framework, applied as
// Organization --org_unit--> Organization only when a human accepts them
// (ai-design-principles.md, principles 9 & 10, which name org_unit a sanctioned
// reviewed write).
//
// A shared or abbreviated name is weak on its own — organizations in different
// jurisdictions share names (principle 8) — so a pair is proposed only when a
// name-hierarchy signal is backed by a strong shared link: the same postal
// address or the same registry identifier, each recorded as witness so the
// conclusion is reconsidered if that evidence changes. Pairs already linked by
// org_unit or subsidiary (for example by the GLEIF collector) are never
// re-proposed.

// orgUnitConfidence is written on an accepted org_unit edge: a
// name-hierarchy match backed by a strong shared link is probable, and a
// human has approved it.
const orgUnitConfidence = 70

// orgUnitKind is the correlator kind: the proposal-ID prefix and the OAM
// relation an accepted proposal creates.
const orgUnitKind = "org_unit"

// orgUnitProfile is what the org-unit search knows about one organization.
type orgUnitProfile struct {
	asset   graph.Asset
	id      string
	name    string
	brand   string
	acronym string
	// addrEdges maps a location's normalized address key to this org's edge to
	// that location; idEdges maps an identifier value to this org's id edge.
	// Both give a strong shared link an edge to witness.
	addrEdges map[string]graph.Relation
	idEdges   map[string]graph.Relation
	// linked holds the organizations already tied to this one by org_unit or
	// subsidiary, in either direction, so a known link is never re-proposed.
	linked map[string]bool
}

// orgUnitCohort is the set of organizations the org-unit sweep compares. When
// the repository supports database-side grouping, it is the union of the
// organizations that share an identifier or a StreetAddress with another — the only
// organizations the sweep can pair (a name match alone never proposes) — so the
// sweep skips the full scan. Otherwise it loads every organization.
func orgUnitCohort(ctx context.Context, g graph.Graph) ([]graph.Asset, error) {
	if cg, ok := g.(CoKeyedGrouper); ok {
		ids, err := coKeyedCohortIDs(ctx, cg, "Organization",
			[]CoKeyKind{CoKeyIdentifier, CoKeyStreetAddress}, dupMaxBucket)
		if err == nil {
			orgs := make([]graph.Asset, 0, len(ids))
			for _, id := range ids {
				if a, err := g.GetAsset(ctx, id); err == nil {
					orgs = append(orgs, a)
				}
			}

			return orgs, nil
		}
		if !errors.Is(err, ErrCoKeyedUnsupported) {
			return nil, err
		}
		// The repository lacks database-side grouping; fall back to the scan.
	}

	return g.FindAssets(ctx, "Organization", time.Time{}, 0)
}

// FindOrgUnits compares the stored organizations and returns review-gated
// org_unit proposals: a parent organization and a unit of it, linked by a
// name-hierarchy signal and a strong shared link. Read-only.
func FindOrgUnits(ctx context.Context, g graph.Graph) (RelationReport, error) {
	report := RelationReport{Kind: orgUnitKind}

	orgs, err := orgUnitCohort(ctx, g)
	if err != nil {
		return report, err
	}

	var profiles []*orgUnitProfile
	for _, o := range orgs {
		name := graph.ContentString(o, "name")
		if name == "" || registrant.IsPrivacyProxyName(name) || semantics.IsPlaceholderOrganization(name) {
			continue
		}
		if graph.IsPlaceholder(o) {
			continue
		}
		profiles = append(profiles, newOrgUnitProfile(ctx, g, o, name))
	}

	// Compare only organizations that share a strong link (the same address or
	// identifier), so a name match alone never yields a proposal (principle 8).
	byKey := map[string][]*orgUnitProfile{}
	for _, p := range profiles {
		for k := range p.addrEdges {
			byKey["addr:"+k] = append(byKey["addr:"+k], p)
		}
		for k := range p.idEdges {
			byKey["id:"+k] = append(byKey["id:"+k], p)
		}
	}

	// what the organizations' documents say is a unit of what stands in for
	// a name hierarchy (document_states_unit)
	docs, err := orgUnitDocuments(ctx, g)
	if err != nil {
		return report, err
	}

	seen := map[[2]string]bool{}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		members := byKey[k]
		if len(members) < 2 || len(members) > dupMaxBucket {
			continue
		}
		for i := 0; i < len(members); i++ {
			for j := i + 1; j < len(members); j++ {
				a, b := members[i], members[j]
				pair := [2]string{a.id, b.id}
				if pair[0] > pair[1] {
					pair[0], pair[1] = pair[1], pair[0]
				}
				if seen[pair] {
					continue
				}
				seen[pair] = true

				if c, ok := orgUnitCandidate(a, b, docs); ok {
					report.Candidates = append(report.Candidates, c)
				}
			}
		}
	}

	sort.Slice(report.Candidates, func(i, j int) bool {
		ci, cj := report.Candidates[i], report.Candidates[j]
		if ci.FromID != cj.FromID {
			return ci.FromID < cj.FromID
		}
		return ci.ToID < cj.ToID
	})
	return report, nil
}

// orgUnitCandidate returns the org_unit proposal a pair warrants, or ok=false
// when they are already linked or show no parent/unit hierarchy, by name or
// by what their documents state.
func orgUnitCandidate(a, b *orgUnitProfile, docs orgUnitDocs) (RelationCandidate, bool) {
	if a.id == b.id || a.linked[b.id] || b.linked[a.id] {
		return RelationCandidate{}, false
	}

	parent, unit, nameSig, ok := orgUnitHierarchy(a, b)
	if !ok {
		parent, unit, nameSig, ok = docs.hierarchy(a, b)
	}
	if !ok {
		return RelationCandidate{}, false
	}

	linkSig, witness := orgUnitStrongLink(parent, unit)
	if linkSig == "" {
		return RelationCandidate{}, false
	}

	return RelationCandidate{
		FromID:     parent.id,
		From:       parent.name,
		Label:      orgUnitKind,
		ToID:       unit.id,
		To:         unit.name,
		Confidence: orgUnitConfidence,
		Signals:    []string{nameSig, linkSig},
		Witness:    witness,
	}, true
}

// orgUnitHierarchy reports which of two organizations is the parent and which
// the unit by name, trying each direction.
func orgUnitHierarchy(a, b *orgUnitProfile) (parent, unit *orgUnitProfile, sig string, ok bool) {
	if s, yes := isUnitOf(a, b); yes {
		return a, b, s, true
	}
	if s, yes := isUnitOf(b, a); yes {
		return b, a, s, true
	}
	return nil, nil, "", false
}

// isUnitOf reports whether unit's name marks it as a unit of parent: the unit's
// name begins with the parent's acronym, or with the parent's whole name, and
// adds a distinguishing qualifier.
func isUnitOf(parent, unit *orgUnitProfile) (string, bool) {
	pb, ub := parent.brand, unit.brand
	if pb == "" || ub == "" || pb == ub {
		return "", false
	}

	// Acronym expansion: the unit's name begins with the parent's acronym,
	// e.g. "SUNY Polytechnic Institute" under "State University of New York".
	if len(parent.acronym) >= 2 && (ub == parent.acronym || strings.HasPrefix(ub, parent.acronym+" ")) {
		return "acronym expansion: " + parent.acronym + " = " + pb, true
	}

	// Name prefix: the unit's name begins with the parent's whole name and adds
	// at least one more word, e.g. "Acme Robotics" under "Acme".
	if strings.HasPrefix(ub, pb+" ") {
		return "name prefix: " + ub + " extends " + pb, true
	}

	return "", false
}

// orgUnitStrongLink returns the strong shared link between two organizations —
// the same postal address or the same identifier — and the edges that witness
// it, or "" when they share none.
func orgUnitStrongLink(a, b *orgUnitProfile) (string, []graph.WitnessEdge) {
	for _, k := range sortedRelationKeys(a.addrEdges) {
		if eb, ok := b.addrEdges[k]; ok {
			ea := a.addrEdges[k]
			return "shared address: " + k, []graph.WitnessEdge{
				witnessOf(ea, "Organization", "StreetAddress"),
				witnessOf(eb, "Organization", "StreetAddress"),
			}
		}
	}
	for _, k := range sortedRelationKeys(a.idEdges) {
		if eb, ok := b.idEdges[k]; ok {
			ea := a.idEdges[k]
			return "shared identifier: " + k, []graph.WitnessEdge{
				witnessOf(ea, "Organization", "Identifier"),
				witnessOf(eb, "Organization", "Identifier"),
			}
		}
	}

	return "", nil
}

func witnessOf(r graph.Relation, fromType, toType string) graph.WitnessEdge {
	return graph.WitnessEdge{EdgeID: r.ID, Label: r.Label, RelationType: r.Type,
		FromID: r.FromID, FromType: fromType, ToID: r.ToID, ToType: toType}
}

func sortedRelationKeys(m map[string]graph.Relation) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// newOrgUnitProfile reads an organization's name, addresses, identifiers and
// existing parent/unit links.
func newOrgUnitProfile(ctx context.Context, g graph.Graph, o graph.Asset, name string) *orgUnitProfile {
	p := &orgUnitProfile{
		asset: o, id: o.ID, name: name,
		brand:     semantics.OrgNameKey(name),
		addrEdges: map[string]graph.Relation{},
		idEdges:   map[string]graph.Relation{},
		linked:    map[string]bool{},
	}
	p.acronym = abbreviation(p.brand, semantics.OrgInitialsStopWords())

	for _, label := range []string{"legal_address", "hq_address", "street_address"} {
		edges, err := g.Edges(ctx, o.ID, "out", label, time.Time{})
		if err != nil {
			continue
		}
		// every address, read in one batch where the graph can
		read, _ := graph.FarAssets(ctx, g, o.ID, edges, nil)
		for _, e := range edges {
			loc, err := graph.AssetFrom(ctx, g, read, e.ToID)
			if err != nil {
				continue
			}
			if k := graph.StreetAddressKey(loc); k != "" {
				if _, ok := p.addrEdges[k]; !ok {
					p.addrEdges[k] = e
				}
			}
		}
	}

	if edges, err := g.Edges(ctx, o.ID, "out", "id", time.Time{}); err == nil {
		read, _ := graph.FarAssets(ctx, g, o.ID, edges, nil)
		for _, e := range edges {
			id, err := graph.AssetFrom(ctx, g, read, e.ToID)
			if err != nil {
				continue
			}
			// Only strong, registry-grade identifiers corroborate ownership.
			idtype := strings.ToLower(strings.TrimSpace(graph.ContentString(id, "id_type")))
			val := strings.ToLower(strings.TrimSpace(graph.ContentString(id, "id")))
			if val == "" || !orgUnitStrongIDType(idtype) {
				continue
			}
			key := idtype + ":" + val
			if _, ok := p.idEdges[key]; !ok {
				p.idEdges[key] = e
			}
		}
	}

	for _, dir := range []string{"out", "in"} {
		for _, label := range []string{"org_unit", "subsidiary"} {
			edges, err := g.Edges(ctx, o.ID, dir, label, time.Time{})
			if err != nil {
				continue
			}
			for _, e := range edges {
				other := e.ToID
				if dir == "in" {
					other = e.FromID
				}
				p.linked[other] = true
			}
		}
	}

	return p
}

// orgUnitStrongIDType reports whether an identifier type is strong enough that
// two organizations sharing it is real corroboration (not a shared email domain
// or social handle).
func orgUnitStrongIDType(idtype string) bool {
	switch idtype {
	case "lei", "registration_id", "duns", "uei", "cik", "sec cik", "ein", "cage":
		return true
	}
	return false
}

// orgUnitDocs maps a unit's and a parent's folded names to the statement
// of a current document that the one is a unit of the other.
type orgUnitDocs map[[2]string]string

// orgUnitDocuments reads what current documents state is a unit of what
// (unit_of findings), by folded names.
func orgUnitDocuments(ctx context.Context, g graph.Graph) (orgUnitDocs, error) {
	findings, err := documentFindings(ctx, g, []string{"unit_of"})
	if err != nil {
		return nil, err
	}

	docs := orgUnitDocs{}
	for _, f := range findings {
		if f.st.SubjectType != "Organization" || f.st.ObjectType != "Organization" {
			continue
		}
		k := [2]string{docFold(f.st.Subject), docFold(f.st.Object)}
		if _, ok := docs[k]; !ok && k[0] != k[1] {
			docs[k] = fmt.Sprintf("a document states %q unit_of %q, in %s", f.st.Subject, f.st.Object, f.url)
		}
	}
	return docs, nil
}

// hierarchy reports which of two organizations a document names as the
// other's parent.
func (docs orgUnitDocs) hierarchy(a, b *orgUnitProfile) (parent, unit *orgUnitProfile, sig string, ok bool) {
	if s, yes := docs[[2]string{docFold(b.name), docFold(a.name)}]; yes {
		return a, b, s, true
	}
	if s, yes := docs[[2]string{docFold(a.name), docFold(b.name)}]; yes {
		return b, a, s, true
	}
	return nil, nil, "", false
}
