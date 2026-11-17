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

// LensIdentifiers asks for the registered identifiers of a domain or
// organization — LEI, tax and company numbers, registry handles and the like
// — attached to the organizations, contacts and other assets it controls. The
// answer is built in Go from stored identifiers; nothing is written.
const LensIdentifiers = "identifiers"

// identifiersExamples bounds the example values kept per identifier type.
const identifiersExamples = 5

var identifiersLens = SubjectLens{
	Name:    LensIdentifiers,
	Command: "identifiers",
	Description: "List the registered identifiers of a domain or organization — LEI, tax, company and registry " +
		"numbers and handles — attached to what it controls, grouped by type. Read-only",
	Examples: []string{"What identifiers are on record for <organization>?",
		"Does <organization> have an LEI or company number?",
		"Which registry handles are tied to <domain>?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindIdentifiers(ctx, g, schema, root, opts.Limits)
	},
}

// IdentifierEntry is one registered identifier and what it is attached to.
type IdentifierEntry struct {
	// Type is the OAM id_type (lei, ein, duns, ocid, arin and so on).
	Type  string `json:"type"`
	Value string `json:"value"`
	// Holder is the label of the asset the identifier is attached to, and
	// HolderType its asset type (usually an Organization).
	Holder     string `json:"holder,omitempty"`
	HolderType string `json:"holder_type,omitempty"`
	Status     string `json:"status,omitempty"`
}

// IdentifiersReport is the result of the identifiers lens.
type IdentifiersReport struct {
	lensBase
	Identifiers []IdentifierEntry `json:"identifiers"`
	// ByType counts the identifiers of each id_type, most common first.
	ByType []ChangeGroup `json:"by_type,omitempty"`
}

// FindIdentifiers lists the registered identifiers attached to what a domain
// or organization controls, grouped by type. It reads only.
func FindIdentifiers(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (IdentifiersReport, error) {
	g = graph.Cached(g)
	var out IdentifiersReport
	s, err := newScope(ctx, g, schema, root, limits, LensIdentifiers)
	if err != nil {
		return out, err
	}

	byType := map[string]*ChangeGroup{}
	var typeOrder []string
	seen := map[string]bool{}

	for _, id := range s.order {
		if s.spent() {
			break
		}
		holder := s.owned[id]
		steps, err := s.w.steps(holder)
		if err != nil {
			return out, err
		}
		for _, st := range steps {
			if !st.forward || st.other.Type != "Identifier" {
				continue
			}
			entry, ok := identifierEntry(st.other, holder)
			if !ok || seen[st.other.ID] {
				continue
			}
			seen[st.other.ID] = true
			out.Identifiers = append(out.Identifiers, entry)

			g, ok := byType[entry.Type]
			if !ok {
				g = &ChangeGroup{Key: entry.Type}
				byType[entry.Type] = g
				typeOrder = append(typeOrder, entry.Type)
			}
			g.Count++
			if len(g.Examples) < identifiersExamples {
				graph.AddUnique(&g.Examples, entry.Value)
			}
		}
	}

	sort.Slice(out.Identifiers, func(i, j int) bool {
		if out.Identifiers[i].Type != out.Identifiers[j].Type {
			return out.Identifiers[i].Type < out.Identifiers[j].Type
		}
		return out.Identifiers[i].Value < out.Identifiers[j].Value
	})
	out.ByType = make([]ChangeGroup, 0, len(typeOrder))
	for _, k := range typeOrder {
		out.ByType = append(out.ByType, *byType[k])
	}
	sort.SliceStable(out.ByType, func(i, j int) bool {
		if out.ByType[i].Count != out.ByType[j].Count {
			return out.ByType[i].Count > out.ByType[j].Count
		}
		return out.ByType[i].Key < out.ByType[j].Key
	})
	out.lensBase = s.base()
	return out, nil
}

// identifierEntry reads a stored identifier and the asset it hangs off.
func identifierEntry(id, holder graph.Asset) (IdentifierEntry, bool) {
	typ := graph.ContentString(id, "id_type")
	value := graph.ContentString(id, "id")
	if value == "" {
		value = graph.AssetLabel(id)
	}
	if typ == "" || value == "" {
		return IdentifierEntry{}, false
	}

	return IdentifierEntry{
		Type:       typ,
		Value:      value,
		Holder:     graph.AssetLabel(holder),
		HolderType: holder.Type,
		Status:     graph.ContentString(id, "status"),
	}, true
}

// Text implements Report.
func (r IdentifiersReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}

	fmt.Fprintf(&b, "Registered identifiers of %s: %d identifier(s) in %d type(s) (%d reads).\n",
		subject, len(r.Identifiers), len(r.ByType), r.Reads)

	if len(r.Identifiers) == 0 {
		b.WriteString("\nNo registered identifier is stored.\n")
		return b.String()
	}

	b.WriteString("\n")
	for _, e := range r.Identifiers {
		fmt.Fprintf(&b, "  %s: %s", strings.ToUpper(e.Type), e.Value)
		if e.Holder != "" {
			fmt.Fprintf(&b, " (%s)", e.Holder)
		}
		if e.Status != "" {
			fmt.Fprintf(&b, " [%s]", e.Status)
		}
		b.WriteString("\n")
	}

	if len(r.ByType) > 0 {
		b.WriteString("\nBy type:\n")
		for _, g := range r.ByType {
			fmt.Fprintf(&b, "  %s: %d\n", strings.ToUpper(g.Key), g.Count)
		}
	}

	b.WriteString("\nThese are stored identifiers, not a live lookup." + r.partialNote() + "\n")
	return b.String()
}

// Facts implements Report.
func (r IdentifiersReport) Facts() []string {
	out := make([]string, 0, len(r.Identifiers))
	for _, e := range r.Identifiers {
		out = append(out, strings.ToUpper(e.Type)+" "+e.Value)
	}
	return out
}
