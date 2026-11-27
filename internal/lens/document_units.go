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

// Units from documents: the offices, departments, campuses and programs an
// organization's own documents name as its units. The document model writes
// the organization that published a document as DocumentPublisher, and a
// unit_of finding with that object is resolved to the publisher here (the
// organization behind the domain the documents were read for). Units are
// listed read-only by the org-group lens (DocumentUnits), and a unit no
// source has stored is proposed for review as a new Organization with an
// org_unit edge from its parent (a doc_relation proposal with NewTo). Nothing
// is written until a reviewer approves.

// DocumentPublisher is the placeholder the document model writes for the
// organization that published the document it reads, in a unit_of finding
// only.
const DocumentPublisher = "PUBLISHER"

// NewAsset is an asset a proposal creates when it is approved: the
// destination of a relationship no source has stored yet.
type NewAsset struct {
	Type string `json:"type"`
	// Key is the asset's unique ID; Name its display name.
	Key  string `json:"key"`
	Name string `json:"name"`
}

// UnitKey is the unique ID of a unit Organization a document names, scoped
// to its parent so that two organizations' units of one name ("Counseling")
// are never one record.
func UnitKey(parent graph.Asset, name string) string {
	id := parent.Key
	if id == "" {
		id = parent.ID
	}
	return id + " / " + strings.Join(strings.Fields(name), " ")
}

// unitOfOther reports whether a stored organization is already a unit or
// subsidiary of an organization other than parent: an office of one name at
// another organization.
func (r *docRelations) unitOfOther(unit, parent graph.Asset) (bool, error) {
	for _, l := range []string{"org_unit", "subsidiary"} {
		edges, err := r.g.Edges(r.ctx, unit.ID, "in", l, time.Time{})
		if err != nil {
			return false, err
		}
		for _, e := range edges {
			if e.FromID != parent.ID {
				return true, nil
			}
		}
	}
	return false, nil
}

// addNewUnit counts a finding that names a unit of parent no source has
// stored (or stored only under another parent) toward a proposal to create
// it. A unit stored under parent's scoped key is linked instead.
func (r *docRelations) addNewUnit(src DocumentSource, st docStatement, sig DocumentSignal,
	parent graph.Asset) error {
	name := strings.Join(strings.Fields(st.Subject), " ")
	if name == "" || docFold(name) == docFold(graph.ContentString(parent, "name")) {
		return nil
	}
	key := UnitKey(parent, name)

	to := graph.Asset{Type: "Organization", Key: key, Content: map[string]any{"unique_id": key, "name": name}}
	if res, err := r.g.ResolveAsset(r.ctx, graph.AssetSelector{Type: "Organization", Field: "unique_id",
		Value: key}, 2); err == nil && len(res.Candidates) == 1 {
		to = res.Candidates[0].Asset
		linked, err := r.isLinked(parent.ID, to.ID, sig.Label)
		if err != nil || linked {
			return err
		}
	}

	found := parent.ID + "\x00" + sig.Label + "\x00" + to.ID
	if to.ID == "" {
		found = parent.ID + "\x00" + sig.Label + "\x00new:" + docFold(name)
	}
	r.count(src, st, sig, found, parent, to)
	return nil
}

// DocumentUnit is a unit an organization's own documents name.
type DocumentUnit struct {
	Name string `json:"name"`
	// Stored reports that the unit is stored as an organization linked to
	// the subject as its unit.
	Stored bool `json:"stored,omitempty"`
	// Documents counts the documents naming it; Examples cites the first.
	Documents int      `json:"documents"`
	Examples  []string `json:"examples,omitempty"`
}

// DocumentUnits returns the units the subject organization's own, current
// documents name: unit_of findings whose parent is the document's publisher
// or the subject by its exact name or legal name. It reads only.
func DocumentUnits(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, subject graph.Asset,
	limits LensLimits) ([]DocumentUnit, error) {
	if subject.Type != "Organization" {
		return nil, nil
	}
	findings, err := rootDocumentFindings(ctx, g, schema, subject, limits, "unit_of")
	if err != nil || len(findings) == 0 {
		return nil, err
	}

	own := map[string]bool{}
	for _, field := range []string{"name", "legal_name"} {
		if n := docFold(graph.ContentString(subject, field)); n != "" {
			own[n] = true
		}
	}
	stored := map[string]bool{}
	if edges, err := g.Edges(ctx, subject.ID, "out", "org_unit", time.Time{}); err == nil {
		for _, e := range edges {
			if a, err := g.GetAsset(ctx, e.ToID); err == nil {
				stored[docFold(graph.ContentString(a, "name"))] = true
			}
		}
	}

	type unit struct {
		u     DocumentUnit
		files map[string]bool
	}
	found := map[string]*unit{}
	for _, f := range findings {
		if f.st.Object != DocumentPublisher && !own[docFold(f.st.Object)] {
			continue
		}
		name := strings.Join(strings.Fields(f.st.Subject), " ")
		key := docFold(name)
		if key == "" || own[key] || key == docFold(DocumentPublisher) {
			continue
		}
		u, ok := found[key]
		if !ok {
			u = &unit{u: DocumentUnit{Name: name, Stored: stored[key]}, files: map[string]bool{}}
			found[key] = u
		}
		if !u.files[f.fileID] {
			u.files[f.fileID] = true
			if len(u.u.Examples) < docLensMaxCited {
				u.u.Examples = append(u.u.Examples, f.url)
			}
		}
	}

	out := make([]DocumentUnit, 0, len(found))
	for _, u := range found {
		u.u.Documents = len(u.files)
		out = append(out, u.u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Documents != out[j].Documents {
			return out[i].Documents > out[j].Documents
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// formatDocumentUnits renders the units a subject's documents name.
func formatDocumentUnits(b *strings.Builder, units []DocumentUnit) {
	if len(units) == 0 {
		return
	}
	fmt.Fprintf(b, "Units its own documents name (%d):\n", len(units))
	for _, u := range units {
		state := "not stored"
		if u.Stored {
			state = "stored"
		}
		fmt.Fprintf(b, "  %s (%s; %d document(s)", u.Name, state, u.Documents)
		if len(u.Examples) > 0 {
			fmt.Fprintf(b, ", e.g. %s", u.Examples[0])
		}
		b.WriteString(")\n")
	}
	b.WriteString("A unit not stored can be added by approving its doc_relation proposal (amass review proposals).\n")
}
