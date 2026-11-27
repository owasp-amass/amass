// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/review"
)

// proposalKind is one kind of review record: how to read it from the journal
// and how the listings, summaries and decision items name it. Every listing
// walks proposalKinds, so a new kind is added once.
type proposalKind struct {
	// name is the kind in DecisionItems; key the kind's field in JSON and in
	// PendingSummary and AppliedSummary.
	name, key string
	// heading introduces the kind's proposals in the listings; empty for a
	// kind that is never listed (a document lead is only ever applied).
	heading string
	// pending and applied are the summary nouns, singular and plural; empty
	// pending for a kind that is never pending (a contribution is applied
	// when the user approves it), empty applied for a kind the AI never
	// applies on its own.
	pending, applied [2]string
	read             func(j *review.Journal) (kindRecords, error)
}

// record is what the listings need of one review record.
type record struct {
	id, status, reviewer string
	// created is when it was proposed; decided when its latest decision was
	// made.
	created, decided time.Time
	// entities are the stored assets it is about.
	entities []string
}

func (r record) isPending() bool { return r.status == review.ProposalPending }

func (r record) appliedByAI(since time.Time) bool {
	return r.status == review.ProposalApplied && isAIReviewer(r.reviewer) &&
		(since.IsZero() || !r.decided.Before(since))
}

// kindRecords are one kind's records, kept in the review package's own
// types so they are formatted and encoded as before.
type kindRecords interface {
	records() []record
	// text formats the records keep chooses, as the review package does.
	text(keep func(record) bool) string
	// entries returns the records keep chooses, for JSON.
	entries(keep func(record) bool) any
	// each calls fn with every record and its text alone.
	each(fn func(r record, text string))
}

type typedRecords[E any] struct {
	list     []E
	describe func(E) record
	format   func([]E) string
}

func (t typedRecords[E]) records() []record {
	out := make([]record, len(t.list))
	for i, e := range t.list {
		out[i] = t.describe(e)
	}
	return out
}

func (t typedRecords[E]) pick(keep func(record) bool) []E {
	out := make([]E, 0, len(t.list))
	for _, e := range t.list {
		if keep == nil || keep(t.describe(e)) {
			out = append(out, e)
		}
	}
	return out
}

func (t typedRecords[E]) text(keep func(record) bool) string { return t.format(t.pick(keep)) }

func (t typedRecords[E]) entries(keep func(record) bool) any { return t.pick(keep) }

func (t typedRecords[E]) each(fn func(r record, text string)) {
	for _, e := range t.list {
		fn(t.describe(e), t.format([]E{e}))
	}
}

// readRecords adapts a journal reader to kindRecords.
func readRecords[E any](load func() ([]E, error), describe func(E) record,
	format func([]E) string) (kindRecords, error) {
	list, err := load()
	if err != nil {
		return nil, err
	}
	return typedRecords[E]{list: list, describe: describe, format: format}, nil
}

// proposalKinds are the kinds of review record, in the order they are listed.
var proposalKinds = []proposalKind{
	{name: "ownership", key: "ownership", heading: "Ownership relationships",
		pending: [2]string{"ownership relationship", "ownership relationships"},
		applied: [2]string{"ownership relationship", "ownership relationships"},
		read: func(j *review.Journal) (kindRecords, error) {
			return readRecords(j.OwnershipEntries, func(e review.OwnershipEntry) record {
				r := record{id: e.Proposal.ID, status: e.Status, created: e.Proposal.CreatedAt,
					entities: []string{e.Proposal.Edge.FromID, e.Proposal.Edge.ToID}}
				if e.Outcome != nil {
					r.reviewer, r.decided = e.Outcome.Reviewer, e.Outcome.At
				}
				return r
			}, review.FormatOwnershipEntries)
		}},
	{name: "merge", key: "merges", heading: "Merge proposals",
		pending: [2]string{"possible duplicate organization", "possible duplicate organizations"},
		applied: [2]string{"organization merge", "organization merges"},
		read: func(j *review.Journal) (kindRecords, error) {
			return readRecords(j.DuplicateEntries, func(e review.DuplicateEntry) record {
				r := record{id: e.Proposal.ID, status: e.Status, created: e.Proposal.CreatedAt,
					entities: []string{e.Proposal.SurvivorID, e.Proposal.DuplicateID}}
				if e.Outcome != nil {
					r.reviewer, r.decided = e.Outcome.Reviewer, e.Outcome.At
				}
				if e.Status == review.ProposalApplied {
					// the merge deleted the duplicate
					r.entities = r.entities[:1]
				}
				return r
			}, review.FormatDuplicateEntries)
		}},
	{name: "identity", key: "identities", heading: "Identity corrections",
		pending: [2]string{"identity correction", "identity corrections"},
		applied: [2]string{"identity correction", "identity corrections"},
		read: func(j *review.Journal) (kindRecords, error) {
			return readRecords(j.IdentityEntries, func(e review.IdentityEntry) record {
				r := record{id: e.Proposal.ID, status: e.Status, created: e.Proposal.CreatedAt,
					entities: []string{e.Proposal.OrgID}}
				if e.Outcome != nil {
					r.reviewer, r.decided = e.Outcome.Reviewer, e.Outcome.At
				}
				return r
			}, review.FormatIdentityEntries)
		}},
	{name: "person_named", key: "person_named", heading: "Organizations recorded under a person's name",
		pending: [2]string{"organization recorded under a person's name",
			"organizations recorded under a person's name"},
		read: func(j *review.Journal) (kindRecords, error) {
			return readRecords(j.PersonNamedEntries, func(e review.PersonNamedEntry) record {
				r := record{id: e.Proposal.ID, status: e.Status, created: e.Proposal.CreatedAt,
					entities: []string{e.Proposal.OrgID, e.Proposal.PersonID}}
				if e.Outcome != nil {
					r.reviewer, r.decided = e.Outcome.Reviewer, e.Outcome.At
				}
				return r
			}, review.FormatPersonNamedEntries)
		}},
	{name: "org_named", key: "org_named", heading: "People recorded under an organization's name",
		pending: [2]string{"person recorded under an organization's name",
			"people recorded under an organization's name"},
		read: func(j *review.Journal) (kindRecords, error) {
			return readRecords(j.OrgNamedEntries, func(e review.OrgNamedEntry) record {
				r := record{id: e.Proposal.ID, status: e.Status, created: e.Proposal.CreatedAt,
					entities: []string{e.Proposal.PersonID}}
				if e.Outcome != nil {
					r.reviewer, r.decided = e.Outcome.Reviewer, e.Outcome.At
				}
				return r
			}, review.FormatOrgNamedEntries)
		}},
	{name: "relation", key: "relations", heading: "Relationship proposals",
		pending: [2]string{"inferred relationship", "inferred relationships"},
		read: func(j *review.Journal) (kindRecords, error) {
			return readRecords(func() ([]review.RelationEntry, error) { return j.RelationEntries("") },
				func(e review.RelationEntry) record {
					return record{id: e.Proposal.ID, status: e.Status, created: e.Proposal.CreatedAt,
						entities: []string{e.Proposal.FromID, e.Proposal.ToID}}
				}, review.FormatRelationEntries)
		}},
	{name: "name_kind", key: "name_kinds", heading: "Names to decide as a person or an organization",
		pending: [2]string{"name to decide as a person or an organization",
			"names to decide as a person or an organization"},
		applied: [2]string{"name decided as a person or an organization",
			"names decided as a person or an organization"},
		read: func(j *review.Journal) (kindRecords, error) {
			return readRecords(j.NameKindEntries, func(e review.NameKindEntry) record {
				r := record{id: e.Proposal.ID, status: e.Status, created: e.Proposal.CreatedAt,
					entities: []string{e.Proposal.RecordID}}
				if e.Outcome != nil {
					r.reviewer, r.decided = e.Outcome.Reviewer, e.Outcome.At
					if e.Status == review.ProposalApplied {
						r.entities = append(r.entities, e.Outcome.EntityID)
					}
				}
				return r
			}, review.FormatNameKindEntries)
		}},
	{name: "scope_expansion", key: "scope_expansions", heading: "Scope expansions",
		pending: [2]string{"scope expansion", "scope expansions"},
		applied: [2]string{"scope expansion", "scope expansions"},
		read: func(j *review.Journal) (kindRecords, error) {
			return readRecords(j.ScopeExpansions, func(e review.ScopeExpansion) record {
				return record{id: e.ID, status: e.Status, reviewer: e.Reviewer, created: e.At, decided: e.At,
					entities: []string{e.OrgID}}
			}, review.FormatScopeExpansions)
		}},
	{name: "contribution", key: "contributions", heading: "Contributions from assistants",
		read: func(j *review.Journal) (kindRecords, error) {
			return readRecords(j.Contributions, func(c review.Contribution) record {
				return record{id: c.ID, status: c.Status, reviewer: c.Reviewer, created: c.At, decided: c.At,
					entities: c.Write.EntityIDs}
			}, review.FormatContributions)
		}},
	{name: "document_lead", key: "document_leads",
		applied: [2]string{"document lead", "document leads"},
		read: func(j *review.Journal) (kindRecords, error) {
			return readRecords(j.DocumentLeads, func(l review.DocumentLead) record {
				return record{id: l.ID, status: l.Status, reviewer: l.Reviewer, created: l.At, decided: l.At,
					entities: []string{l.EntityID}}
			}, formatDocumentLeads)
		}},
}

// formatDocumentLeads describes leads the document model gave enumerations.
func formatDocumentLeads(leads []review.DocumentLead) string {
	var b strings.Builder
	for i, l := range leads {
		if i > 0 {
			b.WriteString("\n")
		}
		kind := l.Type
		if kind == "" {
			kind = "Organization"
		}
		fmt.Fprintf(&b, "Lead given to enumeration %s: the %s %q, named (%s) in %s (read by %s). The engine "+
			"checks it like any other lead; it joins the scope only if attributed.", l.RunID, kind, l.Name,
			l.Predicate, l.URL, l.Model)
		if l.Confirmed && l.Footprint != nil {
			b.WriteString(" " + footprintText(l.Footprint))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// kindSummary phrases count records of a kind, or "" for none.
func kindSummary(n int, nouns [2]string) string {
	if n == 0 || nouns[0] == "" {
		return ""
	}
	return fmt.Sprintf("%d %s", n, plural(n, nouns[0], nouns[1]))
}

// plural picks the singular or plural noun for n.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// listedKinds are the kinds the proposal listings show, each with its
// records read from the journal.
func listedKinds(j *review.Journal) ([]proposalKind, []kindRecords, error) {
	var kinds []proposalKind
	var recs []kindRecords
	for _, k := range proposalKinds {
		if k.heading == "" {
			continue
		}
		r, err := k.read(j)
		if err != nil {
			return nil, nil, err
		}
		kinds, recs = append(kinds, k), append(recs, r)
	}
	return kinds, recs, nil
}
