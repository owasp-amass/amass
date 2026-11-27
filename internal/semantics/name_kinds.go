// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"unicode"
)

// NameKind is what a name found in a person's field names.
type NameKind string

const (
	// NameKindPerson: a person, stored as a Person.
	NameKindPerson NameKind = "person"
	// NameKindOrganization: an organization, stored as an Organization.
	NameKindOrganization NameKind = "organization"
	// NameKindUncertain: the evidence does not settle it; only the raw name
	// is kept until a model or a person decides.
	NameKindUncertain NameKind = "uncertain"
	// NameKindRole: a job or a mailbox ("Domain Administrator"), not anyone.
	NameKindRole NameKind = "role"
)

// NameClues is what is known about a name besides its words.
type NameClues struct {
	// First, Middle and Last are the name as a person's name parser split
	// it; First or Last empty means it does not split as a person's name.
	First, Middle, Last string
	// OrgNames are the organization names the same record gives, such as a
	// registration contact's organization or a document's company.
	OrgNames []string
	// StoredOrg says an organization is already stored under the name.
	StoredOrg bool
	// Emails are the email addresses on the same record.
	Emails []string
}

type nameKindCatalog struct {
	License      string   `json:"_license"`
	About        string   `json:"_about"`
	PersonTitles []string `json:"person_titles"`
	SurnameForms []string `json:"surname_forms"`
	RoleWords    []string `json:"role_words"`
}

type nameKindWords struct {
	titles, surnameForms, roles map[string]bool
}

var loadNameKinds = sync.OnceValue(func() nameKindWords {
	var c nameKindCatalog
	dec := json.NewDecoder(bytes.NewReader(File("name_kinds.json")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("name_kinds.json: " + err.Error())
	}
	if len(c.PersonTitles) == 0 || len(c.RoleWords) == 0 {
		panic("name_kinds.json: person_titles and role_words are required")
	}

	set := func(words []string) map[string]bool {
		m := make(map[string]bool, len(words))
		for _, w := range words {
			m[strings.ToLower(w)] = true
		}
		return m
	}
	return nameKindWords{titles: set(c.PersonTitles), surnameForms: set(c.SurnameForms), roles: set(c.RoleWords)}
})

// NameKindOf decides what a raw name found in a person's field names, and
// gives the reasons (name_kinds.json). A role word makes it a role. Clear
// organization evidence (a legal form, an institution word, a governance
// prefix, the record's own organization naming it, an organization stored
// under it) makes it an organization, unless there is also clear person
// evidence (a title, a middle initial, an email on the record whose mailbox
// spells it), which leaves it uncertain. A name that does not split as a
// person's, or that ends in an institution word that is also a family name,
// is uncertain. Otherwise it is a person.
func NameKindOf(raw string, c NameClues) (NameKind, []string) {
	words := nameWords(raw)
	if len(words) == 0 {
		return NameKindUncertain, []string{"no name"}
	}

	w := loadNameKinds()
	for _, word := range words {
		if w.roles[word] {
			return NameKindRole, []string{"the role word " + word}
		}
	}

	var org, person, weak []string
	leads := loadDocumentLeads()
	for i, word := range words {
		switch {
		case IsOrgLegalForm(word):
			org = append(org, "the legal form "+word)
		case leads.forms[word] && w.surnameForms[word] && i == len(words)-1:
			weak = append(weak, word+" is also a family name")
		case leads.forms[word]:
			org = append(org, "the institution word "+word)
		}
	}
	for _, p := range loadOrgNames().prefixes {
		if len(words) > len(p) && slices.Equal(words[:len(p)], p) {
			org = append(org, "the governance prefix "+strings.Join(p, " "))
			break
		}
	}
	key := OrgNameKey(raw)
	for _, n := range c.OrgNames {
		if key != "" && OrgNameKey(n) == key {
			org = append(org, "the record's organization is "+strings.TrimSpace(n))
			break
		}
	}
	if c.StoredOrg {
		org = append(org, "an organization is stored under the name")
	}

	if w.titles[words[0]] {
		person = append(person, "the title "+words[0])
	}
	if m := nameWords(c.Middle); len(m) > 0 && len([]rune(m[0])) == 1 {
		person = append(person, "the middle initial "+m[0])
	}
	if e := mailboxSpelling(c.First, c.Last, c.Emails); e != "" {
		person = append(person, "the email "+e+" spells it")
	}

	split := strings.TrimSpace(c.First) != "" && strings.TrimSpace(c.Last) != ""
	switch {
	case len(org) > 0 && len(person) > 0:
		return NameKindUncertain, append(org, person...)
	case len(org) > 0:
		return NameKindOrganization, org
	case !split:
		return NameKindUncertain, append(weak, "it does not read as a person's name")
	case len(weak) > 0 && len(person) == 0:
		return NameKindUncertain, weak
	}
	if len(person) == 0 {
		person = []string{"it reads as a person's name"}
	}
	return NameKindPerson, person
}

// nameWords returns a name's words, lower-cased, without surrounding
// punctuation.
func nameWords(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return unicode.IsSpace(r) || r == ','
	}) {
		if f = strings.Trim(f, ".;:'\"()-/"); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// mailboxSpelling returns the first email whose mailbox spells the name:
// the given and family names joined, or the given name's initial and the
// family name ("jsmith", "john.smith", "smith_john").
func mailboxSpelling(first, last string, emails []string) string {
	f, l := lettersOnly(first), lettersOnly(last)
	if f == "" || l == "" {
		return ""
	}
	fi, li := string([]rune(f)[:1]), string([]rune(l)[:1])
	for _, e := range emails {
		box, _, ok := strings.Cut(strings.ToLower(strings.TrimSpace(e)), "@")
		if !ok {
			continue
		}
		switch lettersOnly(box) {
		case f + l, l + f, fi + l, l + fi, f + li:
			return e
		}
	}
	return ""
}

func lettersOnly(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, s)
}
