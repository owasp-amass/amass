// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package semantics describes what each Open Asset Model relationship means
// for AI investigations: whether it can attribute an asset to the party that
// controls it, and what kind of question it helps answer. The table is
// keyed like OAM's relationship table so it can later move into OAM.
package semantics

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed oam_relations.yaml
var raw []byte

// Attribution values; see oam_relations.yaml for their meaning.
const (
	Controller     = "controller"
	Controls       = "controls"
	SameSubject    = "same_subject"
	Shared         = "shared"
	Infrastructure = "infrastructure"
	ThirdParty     = "third_party"
	Attribute      = "attribute"
)

var attributions = map[string]bool{Controller: true, Controls: true, SameSubject: true,
	Shared: true, Infrastructure: true, ThirdParty: true, Attribute: true}

var purposes = map[string]bool{"registration": true, "certificate": true, "corporate": true,
	"contact": true, "network": true, "dns": true, "web": true, "identity": true,
	"financial": true, "product": true, "hierarchy": true}

// Relation is the meaning of one OAM relationship transition.
type Relation struct {
	Source       string `yaml:"source"`
	Label        string `yaml:"label"`
	RelationType string `yaml:"relation_type"`
	Destination  string `yaml:"destination"`
	Attribution  string `yaml:"attribution"`
	Purpose      string `yaml:"purpose"`
	// Review marks an undecided edge; Reviewed records a maintainer decision
	// on an edge whose role varies in practice.
	Review   bool   `yaml:"review"`
	Reviewed bool   `yaml:"reviewed"`
	Note     string `yaml:"note"`
}

// Table holds every relationship's meaning.
type Table struct {
	Version   int        `yaml:"version"`
	Relations []Relation `yaml:"relations"`
	index     map[string]Relation
}

func key(source, label, relationType, destination string) string {
	return source + "\x00" + label + "\x00" + relationType + "\x00" + destination
}

// Load parses and validates the embedded table.
func Load() (*Table, error) {
	return parse(raw)
}

func parse(data []byte) (*Table, error) {
	var t Table
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("parse OAM relation semantics: %w", err)
	}
	if t.Version != 1 {
		return nil, fmt.Errorf("unsupported OAM relation semantics version %d", t.Version)
	}
	if len(t.Relations) == 0 {
		return nil, errors.New("OAM relation semantics table is empty")
	}

	t.index = make(map[string]Relation, len(t.Relations))
	for i, r := range t.Relations {
		if r.Source == "" || r.Label == "" || r.RelationType == "" || r.Destination == "" {
			return nil, fmt.Errorf("relation %d: source, label, relation_type and destination are required", i+1)
		}
		if !attributions[r.Attribution] {
			return nil, fmt.Errorf("%s --%s--> %s: unknown attribution %q", r.Source, r.Label, r.Destination,
				r.Attribution)
		}
		if !purposes[r.Purpose] {
			return nil, fmt.Errorf("%s --%s--> %s: unknown purpose %q", r.Source, r.Label, r.Destination, r.Purpose)
		}
		if r.Note == "" {
			return nil, fmt.Errorf("%s --%s--> %s: a note explaining the choice is required", r.Source,
				r.Label, r.Destination)
		}

		k := key(r.Source, r.Label, r.RelationType, r.Destination)
		if _, dup := t.index[k]; dup {
			return nil, fmt.Errorf("%s --%s/%s--> %s is listed twice", r.Source, r.Label, r.RelationType, r.Destination)
		}

		t.index[k] = r
	}

	return &t, nil
}

// Lookup returns the meaning of one transition.
func (t *Table) Lookup(source, label, relationType, destination string) (Relation, bool) {
	r, ok := t.index[key(source, label, relationType, destination)]
	return r, ok
}
