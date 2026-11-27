// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
)

// StatementOAM maps a statement onto the OAM relation that records the same
// fact: forward is subject --Label--> object, inverse object --Label--> subject.
type StatementOAM struct {
	Label     string `json:"label"`
	Direction string `json:"direction"`
}

// StatementPredicate is something the document model may say a document
// states.
type StatementPredicate struct {
	Name         string        `json:"name"`
	Kind         string        `json:"kind"`
	SubjectTypes []string      `json:"subject_types"`
	ObjectTypes  []string      `json:"object_types"`
	OAM          *StatementOAM `json:"oam,omitempty"`
	Detail       string        `json:"detail,omitempty"`
	Description  string        `json:"description"`
}

// DocumentCategory is what a document may be.
type DocumentCategory struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// StatementKind is a kind of statement a document may make, with the
// inference families that may consume such statements and the vocabulary term
// it follows.
type StatementKind struct {
	Families []string `json:"families"`
	Basis    string   `json:"basis"`
}

// StatementPredicates are the predicates and document categories the document
// model's statements are validated against. Loaded from
// statement_predicates.json; see that file's _about.
type StatementPredicates struct {
	License    string                   `json:"_license"`
	About      string                   `json:"_about"`
	Kinds      map[string]StatementKind `json:"kinds"`
	Predicates []StatementPredicate     `json:"predicates"`
	Categories []DocumentCategory       `json:"categories"`
	byName     map[string]StatementPredicate
	categories map[string]bool
}

var loadStatementPredicates = sync.OnceValue(func() StatementPredicates {
	var s StatementPredicates
	dec := json.NewDecoder(bytes.NewReader(File("statement_predicates.json")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		panic("statement_predicates.json: " + err.Error())
	}
	if len(s.Kinds) == 0 || len(s.Predicates) == 0 || len(s.Categories) == 0 {
		panic("statement_predicates.json: kinds, predicates and categories are required")
	}
	for name, k := range s.Kinds {
		if len(k.Families) == 0 || !strings.HasPrefix(k.Basis, "https://") {
			panic("statement_predicates.json: kind " + name + " needs families and an https basis")
		}
	}

	kinds := s.Kinds
	s.byName = make(map[string]StatementPredicate, len(s.Predicates))
	for _, p := range s.Predicates {
		if p.Name == "" || p.Description == "" || len(p.SubjectTypes) == 0 || len(p.ObjectTypes) == 0 {
			panic("statement_predicates.json: predicate " + p.Name + " needs a name, description and types")
		}
		if _, ok := kinds[p.Kind]; !ok {
			panic("statement_predicates.json: predicate " + p.Name + " names an unknown kind " + p.Kind)
		}
		if _, dup := s.byName[p.Name]; dup {
			panic("statement_predicates.json: predicate " + p.Name + " is repeated")
		}
		if p.OAM != nil && (p.OAM.Label == "" || (p.OAM.Direction != "forward" && p.OAM.Direction != "inverse")) {
			panic("statement_predicates.json: predicate " + p.Name + " needs an OAM label and a forward or inverse direction")
		}
		s.byName[p.Name] = p
	}
	s.categories = make(map[string]bool, len(s.Categories))
	for _, c := range s.Categories {
		if c.Name == "" || c.Description == "" || s.categories[c.Name] {
			panic("statement_predicates.json: category " + c.Name + " is empty or repeated")
		}
		s.categories[c.Name] = true
	}

	return s
})

// StatementPredicateRules returns the statement predicates and categories.
func StatementPredicateRules() StatementPredicates { return loadStatementPredicates() }

// Predicate returns the named predicate.
func (s StatementPredicates) Predicate(name string) (StatementPredicate, bool) {
	p, ok := s.byName[name]
	return p, ok
}

// IsCategory reports whether name is a document category.
func (s StatementPredicates) IsCategory(name string) bool { return s.categories[name] }

// Families returns the inference families that consume the predicate's
// statements, from its kind.
func (s StatementPredicates) Families(p StatementPredicate) []string {
	return s.Kinds[p.Kind].Families
}
