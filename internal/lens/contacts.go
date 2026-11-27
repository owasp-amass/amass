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

// LensContacts asks for the human and organizational contact details of what a
// domain or organization controls: the phone numbers, email addresses, contact
// people and postal addresses, drawn from stored contact records, organization
// members and person records, the mailboxes found at its domains, and what
// its documents contain. The answer is built in Go from stored assets;
// nothing is written.
const LensContacts = "contacts"

var contactsLens = SubjectLens{
	Name:    LensContacts,
	Command: "contacts",
	Description: "Show the contact details of a domain or organization: phone numbers, email addresses, " +
		"contact people and postal addresses, from stored contact records, mailboxes found at its domains and " +
		"its documents. Read-only",
	Examples: []string{"What are <organization>'s contact phone numbers?",
		"Who are the contacts for <domain>?",
		"What addresses and emails are on record for <organization>?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindContacts(ctx, g, schema, root, opts.Limits)
	},
}

// ContactsReport is the result of the contacts lens.
type ContactsReport struct {
	lensBase
	Phones    []string `json:"phones,omitempty"`
	Emails    []string `json:"emails,omitempty"`
	People    []string `json:"people,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	// Sources names, for each phone, email, person and address, where it was
	// found: contactFromRecord, contactFromDomain or contactFromDocument.
	Sources map[string][]string `json:"sources,omitempty"`
}

// Where a contact detail was found.
const (
	// contactFromRecord: a contact record, organization or person names it.
	contactFromRecord = "contact record"
	// contactFromDomain: a mailbox at one of the subject's domains, found by
	// the enumeration (Identifier --registration_agency--> the domain's
	// ContactRecord); shown only when nothing more specific names it.
	contactFromDomain = "collected"
	// contactFromDocument: one of the subject's documents contains it.
	contactFromDocument = "document"
)

// contactSet gathers a report's contact details and where each was found.
type contactSet struct {
	out *ContactsReport
}

func (c contactSet) add(list *[]string, value, source string) {
	if value == "" {
		return
	}
	graph.AddUnique(list, value)
	if c.out.Sources == nil {
		c.out.Sources = map[string][]string{}
	}
	ss := c.out.Sources[value]
	graph.AddUnique(&ss, source)
	c.out.Sources[value] = ss
}

// detail adds the contact detail a is, if it is one.
func (c contactSet) detail(a graph.Asset, source string) {
	switch a.Type {
	case "Phone":
		c.add(&c.out.Phones, phoneLabel(a), source)
	case "Identifier":
		if v, ok := emailValue(a); ok {
			c.add(&c.out.Emails, v, source)
		}
	case "StreetAddress":
		c.add(&c.out.Addresses, streetAddressLabel(a), source)
	case "Person":
		c.add(&c.out.People, personLabel(a), source)
	}
}

// finish sorts the lists and drops contactFromDomain where a more specific
// source names the same detail.
func (c contactSet) finish() {
	for v, ss := range c.out.Sources {
		if len(ss) < 2 {
			continue
		}
		kept := ss[:0]
		for _, src := range ss {
			if src != contactFromDomain {
				kept = append(kept, src)
			}
		}
		sort.Strings(kept)
		c.out.Sources[v] = kept
	}
	sort.Strings(c.out.Phones)
	sort.Strings(c.out.Emails)
	sort.Strings(c.out.People)
	sort.Strings(c.out.Addresses)
}

// domainMailboxes adds the mailboxes found at a domain in the footprint:
// the email plugin links each address to the ContactRecord of its domain
// (Identifier --registration_agency--> ContactRecord --fqdn--> FQDN), so the
// edges point into the record.
func (c contactSet) domainMailboxes(s *scope, fqdn graph.Asset) error {
	name := graph.FQDNName(fqdn)
	steps, err := s.w.steps(fqdn)
	if err != nil {
		return err
	}
	for _, st := range steps {
		if st.forward || st.edge.Label != "fqdn" || st.other.Type != "ContactRecord" ||
			!strings.EqualFold(graph.ContentString(st.other, "discovered_at"), name) {
			continue
		}
		mailboxes, err := s.w.steps(st.other)
		if err != nil {
			return err
		}
		for _, mb := range mailboxes {
			if !mb.forward && mb.edge.Label == "registration_agency" {
				c.detail(mb.other, contactFromDomain)
			}
		}
	}
	return nil
}

// documentContacts adds what the subject's documents contain: the phones,
// email addresses and postal addresses (URL --file--> File --contains-->).
func (c contactSet) documentContacts(s *scope) error {
	urls, err := s.ownedURLs()
	if err != nil {
		return err
	}
	for _, u := range urls {
		if s.spent() {
			break
		}
		steps, err := s.w.steps(u)
		if err != nil {
			return err
		}
		for _, st := range steps {
			if !st.forward || st.other.Type != "File" {
				continue
			}
			contents, err := s.w.steps(st.other)
			if err != nil {
				return err
			}
			for _, ct := range contents {
				if ct.forward && ct.edge.Label == "contains" && ct.other.Type != "Person" {
					c.detail(ct.other, contactFromDocument)
				}
			}
		}
	}
	return nil
}

// FindContacts gathers the contact details tied to a domain or organization,
// from the contact records, members and person records in its footprint, the
// mailboxes found at its domains, and its documents. It reads only.
func FindContacts(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (ContactsReport, error) {
	g = graph.Cached(g)
	var out ContactsReport
	s, err := newScope(ctx, g, schema, root, limits, LensContacts)
	if err != nil {
		return out, err
	}
	c := contactSet{out: &out}

	for _, id := range s.order {
		if s.spent() {
			break
		}
		a := s.owned[id]

		// A person in the footprint is a contact in their own right.
		if a.Type == "Person" {
			c.detail(a, contactFromRecord)
		}
		if a.Type == "FQDN" {
			if err := c.domainMailboxes(s, a); err != nil {
				return out, err
			}
		}

		// Contact records, people and organizations carry the contact
		// attributes; step to them by destination type, not by label.
		if a.Type != "ContactRecord" && a.Type != "Person" && a.Type != "Organization" {
			continue
		}
		steps, err := s.w.steps(a)
		if err != nil {
			return out, err
		}
		for _, st := range steps {
			if st.forward {
				c.detail(st.other, contactFromRecord)
			}
		}
	}
	if err := c.documentContacts(s); err != nil {
		return out, err
	}

	c.finish()
	out.lensBase = s.base()
	return out, nil
}

// phoneLabel is a phone's dialable form.
func phoneLabel(a graph.Asset) string {
	if v := graph.ContentString(a, "e164", "raw"); v != "" {
		return v
	}
	return graph.AssetLabel(a)
}

// emailValue returns an identifier's value when it is an email address.
func emailValue(a graph.Asset) (string, bool) {
	val := graph.ContentString(a, "id")
	if val == "" {
		return "", false
	}
	if strings.EqualFold(graph.ContentString(a, "id_type"), "email") || strings.Contains(val, "@") {
		return val, true
	}
	return "", false
}

// personLabel is a person's name.
func personLabel(a graph.Asset) string {
	if v := graph.ContentString(a, "full_name", "name"); v != "" {
		return v
	}
	return graph.AssetLabel(a)
}

// streetAddressLabel is a readable one-line postal address.
func streetAddressLabel(a graph.Asset) string {
	var parts []string
	for _, k := range []string{"address", "city", "province", "postal_code", "country"} {
		if v := graph.ContentString(a, k); v != "" {
			parts = append(parts, v)
		}
	}
	if len(parts) == 0 {
		return graph.AssetLabel(a)
	}
	return strings.Join(parts, ", ")
}

// Text implements Report.
func (r ContactsReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}

	fmt.Fprintf(&b, "Contacts for %s: %d phone(s), %d email(s), %d person(s), %d address(es) (%d reads).\n",
		subject, len(r.Phones), len(r.Emails), len(r.People), len(r.Addresses), r.Reads)

	if len(r.Phones)+len(r.Emails)+len(r.People)+len(r.Addresses) == 0 {
		b.WriteString("\nNo contact details are stored.\n")
		return b.String()
	}

	group := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s:\n", title)
		for _, it := range items {
			if ss := r.Sources[it]; len(ss) > 0 {
				fmt.Fprintf(&b, "  %s (%s)\n", it, strings.Join(ss, ", "))
				continue
			}
			fmt.Fprintf(&b, "  %s\n", it)
		}
	}
	group("Phones", r.Phones)
	group("Emails", r.Emails)
	group("People", r.People)
	group("Addresses", r.Addresses)

	b.WriteString("\nThese are stored records, not a live lookup: \"" + contactFromRecord +
		"\" is a registration or contact record, \"" + contactFromDocument + "\" one of its documents, and \"" +
		contactFromDomain + "\" an address at its domains found elsewhere by the enumeration." +
		r.partialNote() + "\n")
	return b.String()
}

// Facts implements Report.
func (r ContactsReport) Facts() []string {
	out := make([]string, 0, len(r.Phones)+len(r.Emails)+len(r.People))
	for _, p := range r.Phones {
		out = append(out, "phone "+p)
	}
	for _, em := range r.Emails {
		out = append(out, "email "+em)
	}
	for _, p := range r.People {
		out = append(out, "contact "+p)
	}
	return out
}

// contactTargets returns the assets an owner's ContactRecord names through
// label: owner --via--> ContactRecord --label--> asset, where via is the
// owner's relation to the record, such as contact or issuing_authority.
func contactTargets(ctx context.Context, g graph.Graph, ownerID, via, label string) []graph.Asset {
	crs, err := g.Edges(ctx, ownerID, "out", via, time.Time{})
	if err != nil {
		return nil
	}
	var out []graph.Asset
	for _, ce := range crs {
		targets, err := g.Edges(ctx, ce.ToID, "out", label, time.Time{})
		if err != nil {
			continue
		}
		for _, te := range targets {
			if a, err := g.GetAsset(ctx, te.ToID); err == nil {
				out = append(out, a)
			}
		}
	}
	return out
}
