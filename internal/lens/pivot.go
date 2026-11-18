// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// Bounds on the seed pivot, so resolving a phone or address never fans out
// without limit. A phone usually ties to one organization; an address can tie
// to many, and a registered-agent or shared-building address (for example a
// corporate-services suite that is the registered address of hundreds of
// thousands of companies) ties to so many that pursuing them all would be both
// unaffordable and wrong. These bounds keep the walk cheap and feed the
// shared-address judgement below.
const (
	// PivotMaxOrgs caps how many organizations one seed resolves to; beyond it
	// the set is truncated and marked, never silently dropped.
	PivotMaxOrgs = 50
	// PivotSharedAddressOrgs is the number of organizations at one address
	// above which the address is treated as a shared or registered-agent
	// address: its organizations are reported for review, not auto-seeded.
	PivotSharedAddressOrgs = 10
	// pivotMaxNeighbors bounds how many edges of one kind the walk reads, so a
	// pathological hub cannot force an unbounded read.
	pivotMaxNeighbors = PivotMaxOrgs * 4
)

// PivotOrg is one organization a phone or address resolved to, with the
// registered domains that would seed a normal enumeration and the path that
// tied it to the seed. Domains carry the enumeration value; the path records
// why the organization is a candidate so a reviewer can judge it.
type PivotOrg struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	LegalName string   `json:"legal_name,omitempty"`
	Domains   []string `json:"domains"`
	// Via is how the seed reached the organization: "contact_record" (through a
	// ContactRecord that lists the phone or address) or "address_edge" (the
	// organization's own legal/hq/location address). An address edge, and
	// especially an hq or legal address, is a stronger tie than a shared
	// ContactRecord.
	Via string `json:"via"`
	// Principal is true when the tie is the organization's own hq_address or
	// legal_address: its principal place of business, not an agent address.
	Principal bool `json:"principal,omitempty"`
}

// PivotResolution is the result of resolving a Phone or Location seed to the
// organizations tied to it and the domains those organizations control, so an
// enumeration can start from a phone number or a street address. It is a
// computed view of stored relations, never an authorization: the organizations
// and domains it lists are candidates a human approves before anything is
// enumerated, and a shared address is held for review rather than pursued.
type PivotResolution struct {
	SeedType      string     `json:"seed_type"`
	SeedValue     string     `json:"seed_value"`
	Organizations []PivotOrg `json:"organizations"`
	// Domains is the deduplicated union of the accepted organizations' domains,
	// ranked, ready to seed enumeration. It is empty when the address is shared
	// (held for review) or nothing resolved yet.
	Domains []string `json:"domains"`
	// SharedAddress marks a registered-agent or shared-building address: it ties
	// to more organizations than one approval should enumerate, so its
	// organizations are listed for review and Domains is left empty.
	SharedAddress bool `json:"shared_address,omitempty"`
	// Capped marks that the organization set was truncated at PivotMaxOrgs.
	Capped bool `json:"capped,omitempty"`
}

// ResolveSeedPivot resolves a Phone or Location seed to the organizations tied
// to it and the domains they control, reading only. From a Phone it walks
// Phone ← ContactRecord --organization--> Organization; from a Location it
// walks both the organization's own address edges (legal_address / hq_address /
// location) and Location ← ContactRecord --organization--> Organization. Each
// organization is resolved to its registered domains with the domains lens, so
// a pivot produces the same domain portfolio a later enumeration would. A
// Location that ties to more than PivotSharedAddressOrgs organizations is
// reported as a shared address and left for review rather than seeded.
func ResolveSeedPivot(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, seed graph.Asset,
	limits LensLimits) (PivotResolution, error) {
	out := PivotResolution{SeedType: seed.Type}

	switch seed.Type {
	case "Phone":
		out.SeedValue = graph.ContentString(seed, "e164", "raw")
	case "Location":
		out.SeedValue = graph.ContentString(seed, "address")
	default:
		return out, &pivotError{seed.Type}
	}

	found, err := pivotOrgIDs(ctx, g, seed)
	if err != nil {
		return out, err
	}

	ids := make([]string, 0, len(found))
	for id := range found {
		ids = append(ids, id)
	}
	// A Location shared by many organizations is an agent or shared-building
	// address: report its organizations for review, but do not resolve domains
	// or let the pivot seed an enumeration from them.
	if seed.Type == "Location" && len(ids) > PivotSharedAddressOrgs {
		out.SharedAddress = true
	}
	if len(ids) > PivotMaxOrgs {
		ids = ids[:PivotMaxOrgs]
		out.Capped = true
	}

	for _, id := range ids {
		org, err := g.GetAsset(ctx, id)
		if err != nil || org.Type != "Organization" {
			continue
		}

		po := PivotOrg{
			ID:        id,
			Name:      graph.ContentString(org, "name"),
			LegalName: graph.ContentString(org, "legal_name"),
			Via:       found[id].via,
			Principal: found[id].principal,
		}
		// Resolving domains is the costly step, so skip it for a shared address
		// whose organizations are held for review anyway.
		if !out.SharedAddress {
			po.Domains = orgDomains(ctx, g, schema, org, limits)
		}
		out.Organizations = append(out.Organizations, po)
	}

	rankPivotOrgs(out.Organizations)
	if !out.SharedAddress {
		out.Domains = unionDomains(out.Organizations)
	}
	return out, nil
}

// pivotError reports a seed type the pivot cannot resolve.
type pivotError struct{ typ string }

func (e *pivotError) Error() string {
	return "cannot pivot from a " + e.typ + " seed: only Phone and Location are supported"
}

// pivotTie records how a seed reached an organization.
type pivotTie struct {
	via       string
	principal bool
}

// pivotOrgIDs walks the seed to the organizations tied to it, keyed by ID so a
// duplicate path keeps the strongest tie. It reads only and is bounded by
// pivotMaxNeighbors at each hop.
func pivotOrgIDs(ctx context.Context, g graph.Graph, seed graph.Asset) (map[string]pivotTie, error) {
	out := map[string]pivotTie{}

	switch seed.Type {
	case "Phone":
		// Phone ← ContactRecord --organization--> Organization.
		if err := orgsThroughContactRecords(ctx, g, seed.ID, "phone", out); err != nil {
			return nil, err
		}
	case "Location":
		// The organization's own address edges: its principal place of business
		// (hq/legal) or another recorded location.
		for _, label := range []string{"legal_address", "hq_address", "location"} {
			edges, err := boundedEdges(ctx, g, seed.ID, "in", label)
			if err != nil {
				return nil, err
			}
			principal := label == "legal_address" || label == "hq_address"
			for _, e := range edges {
				record(out, e.FromID, pivotTie{via: "address_edge", principal: principal})
			}
		}
		// Location ← ContactRecord --organization--> Organization.
		if err := orgsThroughContactRecords(ctx, g, seed.ID, "location", out); err != nil {
			return nil, err
		}
	}

	return out, nil
}

// orgsThroughContactRecords walks seed ← ContactRecord (by the given incoming
// label) --organization--> Organization, recording each organization under the
// contact_record path.
func orgsThroughContactRecords(ctx context.Context, g graph.Graph, seedID, label string,
	out map[string]pivotTie) error {
	records, err := boundedEdges(ctx, g, seedID, "in", label)
	if err != nil {
		return err
	}

	for _, r := range records {
		orgs, err := boundedEdges(ctx, g, r.FromID, "out", "organization")
		if err != nil {
			return err
		}
		for _, o := range orgs {
			record(out, o.ToID, pivotTie{via: "contact_record"})
		}
	}

	return nil
}

// record keeps the strongest tie for an organization: an address edge beats a
// contact record, and a principal address beats a non-principal one.
func record(out map[string]pivotTie, id string, t pivotTie) {
	if id == "" {
		return
	}
	if cur, ok := out[id]; ok {
		if cur.via == "address_edge" && t.via != "address_edge" {
			return
		}
		if cur.principal {
			return
		}
	}
	out[id] = t
}

// boundedEdges reads up to pivotMaxNeighbors edges of one direction and label.
func boundedEdges(ctx context.Context, g graph.Graph, id, dir, label string) ([]graph.Relation, error) {
	edges, err := g.Edges(ctx, id, dir, label, time.Time{})
	if err != nil {
		return nil, err
	}
	if len(edges) > pivotMaxNeighbors {
		edges = edges[:pivotMaxNeighbors]
	}
	return edges, nil
}

// orgDomains resolves one organization to its registered domains with the
// domains lens, returning the domain names alone. A resolution error yields no
// domains rather than failing the whole pivot: one organization that cannot be
// walked must not hide the rest.
func orgDomains(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, org graph.Asset,
	limits LensLimits) []string {
	report, err := FindDomains(ctx, g, schema, org, limits)
	if err != nil {
		return nil
	}

	var out []string
	for _, d := range report.Domains {
		if d.Domain != "" {
			out = append(out, d.Domain)
		}
	}
	sort.Strings(out)
	return out
}

// rankPivotOrgs orders organizations so the most seedable come first: a
// principal-address tie before a weaker one, then more domains before fewer,
// then by name for a stable order.
func rankPivotOrgs(orgs []PivotOrg) {
	sort.SliceStable(orgs, func(i, j int) bool {
		if orgs[i].Principal != orgs[j].Principal {
			return orgs[i].Principal
		}
		if len(orgs[i].Domains) != len(orgs[j].Domains) {
			return len(orgs[i].Domains) > len(orgs[j].Domains)
		}
		return strings.ToLower(orgs[i].Name) < strings.ToLower(orgs[j].Name)
	})
}

// unionDomains returns the deduplicated, sorted union of the organizations'
// domains, so the same domain reached through two organizations seeds the
// enumeration once.
func unionDomains(orgs []PivotOrg) []string {
	set := map[string]struct{}{}
	for _, o := range orgs {
		for _, d := range o.Domains {
			set[d] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}

	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
