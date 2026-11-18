// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// Person records already converge on their parsed full name (the entity key),
// so the only duplicates are variant renderings of the same name — a middle
// name or initial present in one and not the other, a title or suffix. A shared
// name is a weak signal on its own, since many people share a name, so a pair
// is proposed only when the two also share a strong link: the same organization
// (both are members of it) or the same identifier (an email, say). The outcome
// is always a review proposal, never an automatic merge: merging two people
// wrongly is costly, and only a human can confirm it.
const (
	// personMaxPersons bounds the persons one whole-database sweep loads.
	personMaxPersons = 5000
	// personMaxLinks bounds how many organization or identifier links one
	// person contributes, so a hub person cannot force an unbounded read.
	personMaxLinks = 200
)

// PersonDuplicate is a proposed-for-review pair of Person records that look
// like the same person: a survivor to keep and a duplicate to merge into it.
type PersonDuplicate struct {
	Survivor    graph.Asset `json:"-"`
	Duplicate   graph.Asset `json:"-"`
	SurvivorID  string      `json:"survivor_id"`
	Survivor_   string      `json:"survivor"`
	DuplicateID string      `json:"duplicate_id"`
	Duplicate_  string      `json:"duplicate"`
	Signals     []string    `json:"signals"`
}

// PersonDuplicateReport is the result of a person-duplicate search.
type PersonDuplicateReport struct {
	Persons    int               `json:"persons"`
	Candidates []PersonDuplicate `json:"candidates"`
	Truncated  string            `json:"truncated,omitempty"`
}

// FormatPersonDuplicateReport renders a person-duplicate search for a terminal.
func FormatPersonDuplicateReport(r PersonDuplicateReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Compared %d persons", r.Persons)
	if r.Truncated != "" {
		fmt.Fprintf(&b, " (truncated: %s)", r.Truncated)
	}
	b.WriteString("\n")
	if len(r.Candidates) == 0 {
		b.WriteString("No likely-duplicate persons found.\n")
		return b.String()
	}
	for _, c := range r.Candidates {
		fmt.Fprintf(&b, "  %s [%s] <- %s [%s]: %s\n", c.Survivor_, c.SurvivorID, c.Duplicate_, c.DuplicateID,
			strings.Join(c.Signals, ", "))
	}
	return b.String()
}

// personProfile holds the name and strong links a person is compared on.
type personProfile struct {
	asset  graph.Asset
	id     string
	full   string
	family string
	first  string
	middle string
	orgs   map[string]bool
	idents map[string]bool
}

// FindPersonDuplicates finds, across the whole database, the Person records
// that look like the same person — a variant of the same name plus a shared
// organization or identifier — and returns them as review candidates. It reads
// only. The whole-database load is bounded by personMaxPersons.
func FindPersonDuplicates(ctx context.Context, g graph.Graph) (PersonDuplicateReport, error) {
	people, err := g.FindAssets(ctx, "Person", time.Time{}, personMaxPersons+1)
	if err != nil {
		return PersonDuplicateReport{}, err
	}

	var report PersonDuplicateReport
	if len(people) > personMaxPersons {
		people = people[:personMaxPersons]
		report.Truncated = fmt.Sprintf("more than %d persons", personMaxPersons)
	}
	report.Persons = len(people)

	// Only persons that share a family name can be the same person, so compare
	// within family-name buckets and skip the singletons: this both bounds the
	// cost and keeps the link walks to persons that could actually match.
	byFamily := map[string][]graph.Asset{}
	for _, p := range people {
		if fam := personNorm(graph.ContentString(p, "family_name")); fam != "" {
			byFamily[fam] = append(byFamily[fam], p)
		}
	}

	report.Candidates = comparePersonBuckets(ctx, g, byFamily, nil)
	return report, nil
}

// ComparePersons compares the given seed persons against one another and the
// candidates, the bounded form the per-run pass uses so its cost tracks what
// the enumeration touched rather than the whole database. seedIDs and
// candidateIDs are Person entity IDs.
func ComparePersons(ctx context.Context, g graph.Graph, seedIDs, candidateIDs []string) (PersonDuplicateReport, error) {
	seeds := map[string]bool{}
	for _, id := range seedIDs {
		seeds[id] = true
	}

	byFamily := map[string][]graph.Asset{}
	for _, id := range append(append([]string{}, seedIDs...), candidateIDs...) {
		p, err := g.GetAsset(ctx, id)
		if err != nil || p.Type != "Person" {
			continue
		}
		if fam := personNorm(graph.ContentString(p, "family_name")); fam != "" {
			byFamily[fam] = append(byFamily[fam], p)
		}
	}

	return PersonDuplicateReport{Candidates: comparePersonBuckets(ctx, g, byFamily, seeds)}, nil
}

// PersonCandidates returns the IDs of other persons that share a strong link —
// an organization they are both members of, or an identifier they both hold —
// with the given person, the bounded candidate set a per-run person-duplicate
// search compares a touched person against. It reads only and is capped.
func PersonCandidates(ctx context.Context, g graph.Graph, personID string) []string {
	p, err := g.GetAsset(ctx, personID)
	if err != nil || p.Type != "Person" {
		return nil
	}
	prof := newPersonProfile(ctx, g, p)

	seen := map[string]bool{personID: true}
	var out []string
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}

	// Other members of each organization this person belongs to.
	for org := range prof.orgs {
		if edges, err := g.Edges(ctx, org, "out", "member", time.Time{}); err == nil {
			for _, e := range edges {
				if len(out) >= personMaxPersons {
					return out
				}
				add(e.ToID)
			}
		}
	}
	// Other holders of each identifier this person holds.
	for id := range prof.idents {
		if edges, err := g.Edges(ctx, id, "in", "id", time.Time{}); err == nil {
			for _, e := range edges {
				if len(out) >= personMaxPersons {
					return out
				}
				add(e.FromID)
			}
		}
	}
	return out
}

// comparePersonBuckets compares the persons within each family-name bucket and
// returns the duplicate candidates. When seeds is non-nil, only pairs involving
// a seed are emitted, so the bounded search reports only what the run touched.
func comparePersonBuckets(ctx context.Context, g graph.Graph, byFamily map[string][]graph.Asset,
	seeds map[string]bool) []PersonDuplicate {
	var out []PersonDuplicate

	for _, bucket := range byFamily {
		if len(bucket) < 2 || len(bucket) > dupMaxBucket {
			continue
		}

		profiles := make([]*personProfile, 0, len(bucket))
		for _, p := range bucket {
			profiles = append(profiles, newPersonProfile(ctx, g, p))
		}

		for i := 0; i < len(profiles); i++ {
			for j := i + 1; j < len(profiles); j++ {
				a, b := profiles[i], profiles[j]
				if seeds != nil && !seeds[a.id] && !seeds[b.id] {
					continue
				}
				if c, ok := comparePersons(a, b); ok {
					out = append(out, c)
				}
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].SurvivorID != out[j].SurvivorID {
			return out[i].SurvivorID < out[j].SurvivorID
		}
		return out[i].DuplicateID < out[j].DuplicateID
	})
	return out
}

// newPersonProfile reads a person's name and strong links.
func newPersonProfile(ctx context.Context, g graph.Graph, p graph.Asset) *personProfile {
	prof := &personProfile{
		asset:  p,
		id:     p.ID,
		full:   graph.ContentString(p, "full_name"),
		family: personNorm(graph.ContentString(p, "family_name")),
		first:  personNorm(graph.ContentString(p, "first_name")),
		middle: personNorm(graph.ContentString(p, "middle_name")),
		orgs:   map[string]bool{},
		idents: map[string]bool{},
	}

	// Organizations the person is a member of: Organization --member--> Person.
	if edges, err := g.Edges(ctx, p.ID, "in", "member", time.Time{}); err == nil {
		for _, e := range edges {
			if len(prof.orgs) >= personMaxLinks {
				break
			}
			prof.orgs[e.FromID] = true
		}
	}
	// Identifiers the person holds: Person --id--> Identifier.
	if edges, err := g.Edges(ctx, p.ID, "out", "id", time.Time{}); err == nil {
		for _, e := range edges {
			if len(prof.idents) >= personMaxLinks {
				break
			}
			prof.idents[e.ToID] = true
		}
	}

	return prof
}

// comparePersons reports whether two person profiles are the same person: a
// variant of the same name and a shared strong link.
func comparePersons(a, b *personProfile) (PersonDuplicate, bool) {
	if a.id == b.id {
		return PersonDuplicate{}, false
	}

	nameSig, ok := variantName(a, b)
	if !ok {
		return PersonDuplicate{}, false
	}

	var linkSigs []string
	if intersects(a.orgs, b.orgs) {
		linkSigs = append(linkSigs, "shared organization")
	}
	if intersects(a.idents, b.idents) {
		linkSigs = append(linkSigs, "shared identifier")
	}
	if len(linkSigs) == 0 {
		return PersonDuplicate{}, false
	}

	surv, dup := a, b
	// Keep the more complete record (the longer full name) as the survivor;
	// break ties on the ID for a stable, deterministic proposal.
	if len(dup.full) > len(surv.full) || (len(dup.full) == len(surv.full) && dup.id < surv.id) {
		surv, dup = b, a
	}

	return PersonDuplicate{
		Survivor: surv.asset, SurvivorID: surv.id, Survivor_: surv.full,
		Duplicate: dup.asset, DuplicateID: dup.id, Duplicate_: dup.full,
		Signals: append([]string{nameSig}, linkSigs...),
	}, true
}

// variantName reports whether two profiles carry the same person's name in
// different renderings: the same family name, a compatible given name, and no
// contradicting middle name.
func variantName(a, b *personProfile) (string, bool) {
	if a.family == "" || a.family != b.family {
		return "", false
	}
	if a.first == "" || b.first == "" {
		return "", false
	}

	// A differing, non-initial middle name marks different people (John A. vs
	// John B. Smith), so it is never a variant.
	if a.middle != "" && b.middle != "" && a.middle != b.middle &&
		!initialOf(a.middle, b.middle) && !initialOf(b.middle, a.middle) {
		return "", false
	}

	switch {
	case a.first == b.first:
		return "same given and family name", true
	case initialOf(a.first, b.first) || initialOf(b.first, a.first):
		return "same family name, given name by initial", true
	}
	return "", false
}

// intersects reports whether two sets share any member.
func intersects(a, b map[string]bool) bool {
	// Iterate the smaller set.
	if len(b) < len(a) {
		a, b = b, a
	}
	for k := range a {
		if b[k] {
			return true
		}
	}
	return false
}

// initialOf reports whether short is a single-letter initial of full (so "j"
// matches "john").
func initialOf(short, full string) bool {
	return len(short) == 1 && len(full) >= 1 && short[0] == full[0]
}

// personNorm lowercases a name part and collapses non-alphanumeric runs to a
// single space, so renderings compare without casing or punctuation noise.
func personNorm(s string) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			space = false
		case !space:
			b.WriteByte(' ')
			space = true
		}
	}
	return strings.TrimSpace(b.String())
}
