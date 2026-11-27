// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// LensCompare asks what two domains or organizations share.
const LensCompare = "compare"

var compareLens = SubjectLens{
	Name:       LensCompare,
	Command:    "compare",
	NeedsOther: true,
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindShared(ctx, g, schema, root, opts.Other, opts.Limits)
	},
}

// CompareReport is the result of the compare lens.
type CompareReport struct {
	A        lensBase `json:"a"`
	B        lensBase `json:"b"`
	ASubject string   `json:"a_subject"`
	BSubject string   `json:"b_subject"`
	OnlyA    int      `json:"only_a"`
	OnlyB    int      `json:"only_b"`
	// Shared are the assets both control, by type; SharedVendors the
	// outside parties both depend on.
	Shared        []ChangeGroup `json:"shared"`
	SharedVendors []ChangeGroup `json:"shared_vendors"`
}

// FindShared compares the controlled footprints of two domains or
// organizations and the outside parties each depends on, and reports what
// they share: the same netblocks, certificates, contacts or organizations,
// and the same vendors. Sharing is a lead to a relationship (one
// organization, an affiliate, a common supplier), not proof of one. It
// reads only.
func FindShared(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, a, b graph.Asset,
	limits LensLimits) (CompareReport, error) {
	var out CompareReport
	if b.ID == "" {
		return out, errors.New("the compare lens needs a second subject")
	}
	if a.ID == b.ID {
		return out, errors.New("the compare lens needs two different subjects")
	}

	sa, err := newScope(ctx, g, schema, a, limits, "compare")
	if err != nil {
		return out, err
	}
	sb, err := newScope(ctx, g, schema, b, limits, "compare")
	if err != nil {
		return out, err
	}
	out.A, out.B, out.ASubject, out.BSubject = sa.base(), sb.base(), sa.subject(), sb.subject()

	shared := changeTally{examples: 5, groups: map[string]map[string]*ChangeGroup{}}
	for _, id := range sa.order {
		x := sa.owned[id]
		if _, ok := sb.owned[id]; ok {
			shared.add("shared", x.Type, graph.AssetLabel(x))
		} else {
			out.OnlyA++
		}
	}
	for id := range sb.owned {
		if _, ok := sa.owned[id]; !ok {
			out.OnlyB++
		}
	}
	out.Shared = shared.list("shared")

	va, err := SearchThirdPartiesWithin(ctx, g, schema, a, limits)
	if err != nil {
		return out, err
	}
	vb, err := SearchThirdPartiesWithin(ctx, g, schema, b, limits)
	if err != nil {
		return out, err
	}
	inB := map[string]VendorUse{}
	for _, v := range vb.Vendors {
		inB[partyKey(v.Vendor)] = v
	}
	for _, v := range va.Vendors {
		if w, ok := inB[partyKey(v.Vendor)]; ok {
			kinds := []string{v.Kind}
			graph.AddUnique(&kinds, w.Kind)
			out.SharedVendors = append(out.SharedVendors, ChangeGroup{Key: v.Vendor, Count: v.Assets + w.Assets,
				Examples: kinds})
		}
	}
	sort.Slice(out.SharedVendors, func(i, j int) bool {
		if out.SharedVendors[i].Count != out.SharedVendors[j].Count {
			return out.SharedVendors[i].Count > out.SharedVendors[j].Count
		}
		return out.SharedVendors[i].Key < out.SharedVendors[j].Key
	})
	out.A.Reads += va.Reads
	out.B.Reads += vb.Reads
	return out, nil
}

// Partial implements Report.
func (r CompareReport) Partial() (bool, string) {
	if r.A.Truncated {
		return true, r.A.Reason
	}
	return r.B.Truncated, r.B.Reason
}

// Text implements Report.
func (r CompareReport) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Comparing %s (%d controlled asset(s)) with %s (%d).\n", r.ASubject, r.A.Footprint, r.BSubject,
		r.B.Footprint)

	shared := 0
	for _, g := range r.Shared {
		shared += g.Count
	}
	fmt.Fprintf(&b, "Both control %d asset(s); %d are only the first's and %d only the second's.\n", shared,
		r.OnlyA, r.OnlyB)
	if len(r.Shared) > 0 {
		b.WriteString("\nShared assets, by type:\n")
		for _, g := range r.Shared {
			fmt.Fprintf(&b, "  %s: %d, e.g. %s\n", g.Key, g.Count, strings.Join(g.Examples, "; "))
		}
	}
	if len(r.SharedVendors) > 0 {
		b.WriteString("\nOutside parties both depend on:\n")
		for _, v := range r.SharedVendors {
			fmt.Fprintf(&b, "  %s (%s)\n", v.Key, strings.Join(v.Examples, ", "))
		}
	} else {
		b.WriteString("\nThey depend on no outside party in common.\n")
	}

	b.WriteString("Sharing is a lead to a relationship, not proof of one.")
	if partial, reason := r.Partial(); partial {
		fmt.Fprintf(&b, " Results are partial (%s); raise -max-assets or -max-reads to cover more.", reason)
	}
	b.WriteString("\n")
	return b.String()
}

// Facts implements Report.
func (r CompareReport) Facts() []string {
	var out []string
	for _, g := range r.Shared {
		for _, e := range g.Examples {
			out = append(out, "shared "+g.Key+" "+e)
		}
	}
	for _, v := range r.SharedVendors {
		out = append(out, "shared vendor "+v.Key)
	}
	return out
}
