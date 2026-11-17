// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// LensContacts asks for the human and organizational contact details of what a
// domain or organization controls: the phone numbers, email addresses, contact
// people and postal addresses, drawn from stored contact records, organization
// members and person records. The answer is built in Go from stored assets;
// nothing is written.
const LensContacts = "contacts"

var contactsLens = SubjectLens{
	Name:    LensContacts,
	Command: "contacts",
	Description: "Show the contact details of a domain or organization: phone numbers, email addresses, " +
		"contact people and postal addresses, from stored contact records. Read-only",
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
}

// FindContacts gathers the contact details tied to a domain or organization,
// from the contact records, members and person records in its footprint. It
// reads only.
func FindContacts(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (ContactsReport, error) {
	g = graph.Cached(g)
	var out ContactsReport
	s, err := newScope(ctx, g, schema, root, limits, LensContacts)
	if err != nil {
		return out, err
	}

	for _, id := range s.order {
		if s.spent() {
			break
		}
		a := s.owned[id]

		// A person in the footprint is a contact in their own right.
		if a.Type == "Person" {
			if n := personLabel(a); n != "" {
				graph.AddUnique(&out.People, n)
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
			if !st.forward {
				continue
			}
			switch st.other.Type {
			case "Phone":
				graph.AddUnique(&out.Phones, phoneLabel(st.other))
			case "Identifier":
				if v, ok := emailValue(st.other); ok {
					graph.AddUnique(&out.Emails, v)
				}
			case "Location":
				graph.AddUnique(&out.Addresses, locationLabel(st.other))
			case "Person":
				if n := personLabel(st.other); n != "" {
					graph.AddUnique(&out.People, n)
				}
			}
		}
	}

	sort.Strings(out.Phones)
	sort.Strings(out.Emails)
	sort.Strings(out.People)
	sort.Strings(out.Addresses)
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

// locationLabel is a readable one-line postal address.
func locationLabel(a graph.Asset) string {
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
			fmt.Fprintf(&b, "  %s\n", it)
		}
	}
	group("Phones", r.Phones)
	group("Emails", r.Emails)
	group("People", r.People)
	group("Addresses", r.Addresses)

	b.WriteString("\nThese are stored contact records, not a live lookup." + r.partialNote() + "\n")
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
