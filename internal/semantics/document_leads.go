// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed document_leads.json
var documentLeadsJSON []byte

type documentLeadCatalog struct {
	License      string   `json:"_license"`
	About        string   `json:"_about"`
	EntityForms  []string `json:"entity_forms"`
	GenericWords []string `json:"generic_words"`
	Particles    []string `json:"particles"`
}

type documentLeadWords struct {
	forms, generic, particles map[string]bool
}

var loadDocumentLeads = sync.OnceValue(func() documentLeadWords {
	var c documentLeadCatalog
	dec := json.NewDecoder(bytes.NewReader(documentLeadsJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("document_leads.json: " + err.Error())
	}
	if len(c.EntityForms) == 0 || len(c.GenericWords) == 0 {
		panic("document_leads.json: entity_forms and generic_words are required")
	}

	set := func(words []string) map[string]bool {
		m := make(map[string]bool, len(words))
		for _, w := range words {
			m[strings.ToLower(w)] = true
		}
		return m
	}
	return documentLeadWords{forms: set(c.EntityForms), generic: set(c.GenericWords), particles: set(c.Particles)}
})

// GenericOrganizationName reports whether an organization name a document
// names is too generic to be a lead: it has no entity form word
// ("Association", "College") or legal form ("Inc"), and every word other than
// particles is a generic office or service word ("Counseling", "Health
// Center", "Rapid Response").
// A name with no words is not generic.
func GenericOrganizationName(name string) bool {
	w := loadDocumentLeads()
	words := 0
	for _, f := range strings.Fields(strings.ToLower(name)) {
		f = strings.Trim(f, ".,;:'\"()-/")
		if f == "" || w.particles[f] {
			continue
		}
		if w.forms[f] || IsOrgLegalForm(f) || !w.generic[f] {
			return false
		}
		words++
	}
	return words > 0
}
