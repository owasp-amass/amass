// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// Person records already converge on their parsed full name (the entity key),
// so the only duplicates are variant renderings of the same name — a middle
// name or initial present in one and not the other, a title or suffix. A shared
// name is a weak signal on its own, since many people share a name, so a pair
// is proposed only when the two also share a strong link: the same organization
// (both are members of it) or the same identifier (an email, say). The outcome
// is always a review proposal, never an automatic merge: merging two people
// wrongly is costly, and only a human can confirm it.
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
}

// FormatPersonDuplicateReport renders a person-duplicate search for a terminal.
func FormatPersonDuplicateReport(r PersonDuplicateReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Compared %d persons", r.Persons)
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
	asset graph.Asset
	id    string
	full  string
	// names are the person's names: the record's, then the others it is
	// known by (graph.PersonAlias)
	names  []personName
	orgs   map[string]bool
	idents map[string]bool
}

// personName is one rendering of a person's name, in plain text.
type personName struct {
	first, middle, family string
}

// PersonAliasFamily is the family name of another name a person is known
// by, for its person_name_key (PersonNameKey).
func PersonAliasFamily(full string) string {
	return aliasName(full).family
}

// aliasName reads another name the person is known by as given name, middle
// names and family name.
func aliasName(full string) personName {
	words := strings.Fields(semantics.PlainText(full))
	switch len(words) {
	case 0:
		return personName{}
	case 1:
		return personName{family: words[0]}
	}
	return personName{first: words[0], middle: strings.Join(words[1:len(words)-1], " "),
		family: words[len(words)-1]}
}

// personDuplicateCohort is the set of persons the sweep compares. When the
// repository supports database-side grouping, it is the union of the persons
// that share a family-name key with another (the only persons that can bucket
// together), so the sweep skips the full load. Otherwise it loads every
// person.
func personDuplicateCohort(ctx context.Context, g graph.Graph) ([]graph.Asset, error) {
	if cg, ok := g.(CoKeyedGrouper); ok {
		ids, err := coKeyedCohortIDs(ctx, cg, "Person", []CoKeyKind{CoKeyPersonName}, dupMaxBucket)
		if err == nil {
			people := make([]graph.Asset, 0, len(ids))
			for _, id := range ids {
				if a, err := g.GetAsset(ctx, id); err == nil && a.Type == "Person" {
					people = append(people, a)
				}
			}

			return people, nil
		}
		if !errors.Is(err, ErrCoKeyedUnsupported) {
			return nil, err
		}
		// The repository lacks database-side grouping; fall back to the load.
	}

	return g.FindAssets(ctx, "Person", time.Time{}, 0)
}

// FindPersonDuplicates finds, across the whole database, the Person records
// that look like the same person — a variant of the same name plus a shared
// organization or identifier — and returns them as review candidates. It reads
// only.
func FindPersonDuplicates(ctx context.Context, g graph.Graph) (PersonDuplicateReport, error) {
	people, err := personDuplicateCohort(ctx, g)
	if err != nil {
		return PersonDuplicateReport{}, err
	}

	var report PersonDuplicateReport
	report.Persons = len(people)

	report.Candidates = comparePersonBuckets(ctx, g, people, nil)
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

	var people []graph.Asset
	seen := map[string]bool{}
	for _, id := range append(append([]string{}, seedIDs...), candidateIDs...) {
		p, err := g.GetAsset(ctx, id)
		if err != nil || p.Type != "Person" || seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		people = append(people, p)
	}

	return PersonDuplicateReport{Candidates: comparePersonBuckets(ctx, g, people, seeds)}, nil
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
				add(e.ToID)
			}
		}
	}
	// Other holders of each identifier this person holds.
	for id := range prof.idents {
		if edges, err := g.Edges(ctx, id, "in", "id", time.Time{}); err == nil {
			for _, e := range edges {
				add(e.FromID)
			}
		}
	}
	return out
}

// comparePersonBuckets compares the persons that share a family name, by
// any name each is known by (a maiden name kept as another name meets the
// married one), and returns the duplicate candidates. Only persons that
// share a family name can be the same person, so comparing within those
// buckets and skipping the singletons bounds the cost and keeps the link
// walks to persons that could actually match. When seeds is non-nil, only
// pairs involving a seed are emitted, so the bounded search reports only
// what the run touched.
func comparePersonBuckets(ctx context.Context, g graph.Graph, people []graph.Asset,
	seeds map[string]bool) []PersonDuplicate {
	aliases := make(map[string][]string, len(people))
	byFamily := map[string][]graph.Asset{}
	for _, p := range people {
		aliases[p.ID] = personAliases(ctx, g, p)
		for _, fam := range personFamilyKeys(p, aliases[p.ID]) {
			byFamily[fam] = append(byFamily[fam], p)
		}
	}

	var out []PersonDuplicate
	profiles := map[string]*personProfile{}
	profile := func(p graph.Asset) *personProfile {
		if prof, ok := profiles[p.ID]; ok {
			return prof
		}
		prof := newPersonProfileWith(ctx, g, p, aliases[p.ID])
		profiles[p.ID] = prof
		return prof
	}
	compared := map[[2]string]bool{}
	for _, bucket := range byFamily {
		if len(bucket) < 2 || len(bucket) > dupMaxBucket {
			continue
		}

		for i := 0; i < len(bucket); i++ {
			for j := i + 1; j < len(bucket); j++ {
				pair := [2]string{min(bucket[i].ID, bucket[j].ID), max(bucket[i].ID, bucket[j].ID)}
				if compared[pair] || (seeds != nil && !seeds[pair[0]] && !seeds[pair[1]]) {
					continue
				}
				compared[pair] = true
				if c, ok := comparePersons(profile(bucket[i]), profile(bucket[j])); ok {
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

// personAliases are the other names a person is known by
// (graph.PersonAlias).
func personAliases(ctx context.Context, g graph.Graph, p graph.Asset) []string {
	// every name the person is known by
	ev, err := g.Evidence(ctx, p.ID, allEvidence)
	if err != nil {
		return nil
	}
	return propertyValues(ev, graph.PersonAlias)
}

// personFamilyKeys are the family names a person is known by: the
// record's, then each other name's, once each.
func personFamilyKeys(p graph.Asset, aliases []string) []string {
	var keys []string
	add := func(fam string) {
		if fam != "" && !slices.Contains(keys, fam) {
			keys = append(keys, fam)
		}
	}
	add(PersonNameKey(graph.ContentString(p, "family_name")))
	for _, a := range aliases {
		add(PersonNameKey(PersonAliasFamily(a)))
	}
	return keys
}

// newPersonProfile reads a person's name, the other names it is known by
// and its strong links.
func newPersonProfile(ctx context.Context, g graph.Graph, p graph.Asset) *personProfile {
	return newPersonProfileWith(ctx, g, p, personAliases(ctx, g, p))
}

// newPersonProfileWith reads a person's strong links, with the other names
// it is known by already read.
func newPersonProfileWith(ctx context.Context, g graph.Graph, p graph.Asset, aliases []string) *personProfile {
	prof := &personProfile{
		asset: p,
		id:    p.ID,
		full:  graph.ContentString(p, "full_name"),
		names: []personName{{
			family: semantics.PlainText(graph.ContentString(p, "family_name")),
			first:  semantics.PlainText(graph.ContentString(p, "first_name")),
			middle: semantics.PlainText(graph.ContentString(p, "middle_name")),
		}},
		orgs:   map[string]bool{},
		idents: map[string]bool{},
	}
	for _, alias := range aliases {
		prof.names = append(prof.names, aliasName(alias))
	}

	// Organizations the person is a member of: Organization --member--> Person.
	if edges, err := g.Edges(ctx, p.ID, "in", "member", time.Time{}); err == nil {
		for _, e := range edges {
			prof.orgs[e.FromID] = true
		}
	}
	// Identifiers the person holds: Person --id--> Identifier.
	if edges, err := g.Edges(ctx, p.ID, "out", "id", time.Time{}); err == nil {
		for _, e := range edges {
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
// different renderings, comparing every name each is known by.
func variantName(a, b *personProfile) (string, bool) {
	for _, na := range a.names {
		for _, nb := range b.names {
			if sig, ok := variantOf(na, nb); ok {
				return sig, true
			}
		}
	}
	return "", false
}

// variantOf reports whether two names are renderings of the same person's:
// the same family name, a compatible given name, and no contradicting middle
// name.
func variantOf(a, b personName) (string, bool) {
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
