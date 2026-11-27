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

// LensGroupVendors asks for the outside parties a whole corporate group
// depends on. The answer is built in Go; nothing is written.
const LensGroupVendors = "group_vendors"

// groupVendorMinReads is the smallest share of an optional read limit one
// scope is given.
const groupVendorMinReads = 1000

// groupReadShare is the read limit for scope i of n when an optional read
// limit (budget) is shared across a group's scopes, spent reads in: an even
// share of what is left, at least min. ok is false when too little is left
// for another scope. With no budget, a scope has no read limit either.
func groupReadShare(budget, spent, i, n, least int) (limit int, ok bool) {
	if budget == 0 {
		return 0, true
	}

	remaining := budget - spent
	if remaining < least {
		return 0, false
	}
	return min(max(remaining/(n-i), least), remaining), true
}

// GroupVendorUse is one outside party across a corporate group: how many of
// the group's organizations depend on it and for what.
type GroupVendorUse struct {
	Vendor   string   `json:"vendor"`
	VendorID string   `json:"vendor_id,omitempty"`
	Kinds    []string `json:"kinds"`
	Assets   int      `json:"assets"`
	UsedBy   []string `json:"used_by"`
	Examples []string `json:"examples"`
}

// GroupScope is one organization (or the asked-about domain) whose
// dependencies were scanned.
type GroupScope struct {
	Name      string `json:"name"`
	AssetID   string `json:"asset_id"`
	Footprint int    `json:"footprint"`
	Reads     int    `json:"reads"`
	Truncated bool   `json:"truncated,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// GroupVendorReport is the result of the group vendor rollup.
type GroupVendorReport struct {
	Group  GroupReport  `json:"group"`
	Scopes []GroupScope `json:"scopes"`
	// Vendors are outside parties; Internal are parties that are themselves
	// organizations of the group, such as a subsidiary hosting another's
	// services.
	Vendors  []GroupVendorUse `json:"vendors"`
	Internal []GroupVendorUse `json:"internal,omitempty"`
	Reads    int              `json:"reads"`
	// Skipped counts group organizations not scanned because of the scope or
	// read bounds.
	Skipped   int    `json:"skipped,omitempty"`
	Truncated bool   `json:"truncated"`
	Reason    string `json:"reason,omitempty"`
}

// FindGroupVendors runs the vendors walk for each organization of a corporate
// group, and for the domain when root is one, and merges the outside parties
// they depend on, recording which organizations use each. The read budget
// in limits is shared across the group. It reads only.
func FindGroupVendors(ctx context.Context, gr graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (GroupVendorReport, error) {
	var out GroupVendorReport
	if err := limits.Validate(); err != nil {
		return out, err
	}

	group, err := FindCorporateGroup(ctx, gr, root)
	if err != nil {
		return out, err
	}
	out.Group = group
	out.Reads = group.Reads
	if group.Truncated {
		out.truncate("org-group: " + group.Reason)
	}

	// The organizations come first and the domain last: an asset is scanned
	// once, by the first scope that controls it, so the domain adds only the
	// names its organization's records do not reach.
	scopes := make([]graph.Asset, 0, len(group.Members)+1)
	members := map[string]bool{}
	names := map[string]bool{}
	for _, m := range group.Members {
		scopes = append(scopes, m.Organization)
		members[m.Organization.ID] = true
		names[familyKey(graph.AssetLabel(m.Organization))] = true
	}
	if root.Type == "FQDN" {
		scopes = append(scopes, root)
	}

	scanned := map[string]bool{}
	merged := map[string]*GroupVendorUse{}
	var order []string
	budget := limits.MaxReads
	for i, scope := range scopes {
		if err := ctx.Err(); err != nil {
			return out, err
		}

		share, ok := groupReadShare(budget, out.Reads, i, len(scopes), groupVendorMinReads)
		if !ok {
			out.Skipped += len(scopes) - i
			out.truncate("database read limit")
			break
		}

		// Each organization is scanned on its own: a parent's scan does not
		// follow its subsidiaries, which have scans of their own.
		stop := map[string]bool{}
		for id := range members {
			if id != scope.ID {
				stop[id] = true
			}
		}
		r, err := searchThirdPartiesScoped(ctx, gr, schema, scope,
			limits.withReads(share), stop, scanned)
		if err != nil {
			return out, fmt.Errorf("vendors of %s: %w", graph.AssetLabel(scope), err)
		}

		name := graph.AssetLabel(scope)
		out.Reads += r.Reads
		out.Scopes = append(out.Scopes, GroupScope{Name: name, AssetID: scope.ID, Footprint: r.Footprint,
			Reads: r.Reads, Truncated: r.Truncated, Reason: r.Reason})
		for _, v := range r.Vendors {
			key := partyKey(v.Vendor)
			g, ok := merged[key]
			if !ok {
				g = &GroupVendorUse{Vendor: v.Vendor, VendorID: v.VendorID}
				merged[key] = g
				order = append(order, key)
			}
			g.Assets += v.Assets
			if g.VendorID == "" {
				g.VendorID = v.VendorID
			}
			graph.AddUnique(&g.Kinds, v.Kind)
			graph.AddUnique(&g.UsedBy, name)
			for _, e := range v.Examples {
				if len(g.Examples) < 3 {
					graph.AddUnique(&g.Examples, e)
				}
			}
		}
	}

	for _, key := range order {
		g := merged[key]
		sort.Strings(g.Kinds)
		if (g.VendorID != "" && members[g.VendorID]) || names[familyKey(g.Vendor)] {
			out.Internal = append(out.Internal, *g)
		} else {
			out.Vendors = append(out.Vendors, *g)
		}
	}
	for _, list := range [][]GroupVendorUse{out.Vendors, out.Internal} {
		sort.SliceStable(list, func(i, j int) bool {
			a, b := list[i], list[j]
			if len(a.UsedBy) != len(b.UsedBy) {
				return len(a.UsedBy) > len(b.UsedBy)
			}
			if a.Assets != b.Assets {
				return a.Assets > b.Assets
			}
			return a.Vendor < b.Vendor
		})
	}

	return out, nil
}

func (r *GroupVendorReport) truncate(reason string) {
	truncateOnce(&r.Truncated, &r.Reason, reason)
}

// FormatGroupVendorReport renders the group vendor rollup for a terminal.
func FormatGroupVendorReport(r GroupVendorReport) string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Group.Subject)
	fmt.Fprintf(&b, "Vendors across the corporate group of %s: %d organization(s) in the group, %d scanned "+
		"(%d reads).\n", subject, len(r.Group.Members), len(r.Scopes), r.Reads)
	if len(r.Group.Members) <= 1 {
		b.WriteString("No parent, subsidiary or unit is stored, so this covers the one organization; " +
			"`amass lens org-group` shows what the group links are.\n")
	}

	write := func(uses []GroupVendorUse) {
		for _, u := range uses {
			fmt.Fprintf(&b, "  %s: used by %d of %d (%s); %d asset(s), %s", u.Vendor, len(u.UsedBy), len(r.Scopes),
				strings.Join(u.UsedBy, "; "), u.Assets, strings.Join(u.Kinds, ", "))
			if len(u.Examples) > 0 {
				fmt.Fprintf(&b, "; e.g. %s", strings.Join(u.Examples, ", "))
			}
			b.WriteString("\n")
		}
	}

	if len(r.Vendors) == 0 {
		b.WriteString("No outside party was found.\n")
	} else {
		b.WriteString("\nOutside parties, most widely used first:\n")
		write(r.Vendors)
	}
	if len(r.Internal) > 0 {
		b.WriteString("\nServices one group organization provides another:\n")
		write(r.Internal)
	}

	var partial []string
	for _, s := range r.Scopes {
		if s.Truncated {
			partial = append(partial, fmt.Sprintf("%s (%s)", s.Name, s.Reason))
		}
	}
	if len(partial) > 0 {
		fmt.Fprintf(&b, "\nPartial scans: %s.\n", strings.Join(partial, "; "))
	}

	b.WriteString("These are stored OAM relationships, not verified contracts or current service use.")
	if r.Truncated {
		fmt.Fprintf(&b, " Results are partial (%s)", r.Reason)
		if r.Skipped > 0 {
			fmt.Fprintf(&b, "; %d organization(s) were not scanned", r.Skipped)
		}
		b.WriteString(partialAdvice(r.Reason))
	}
	b.WriteString("\n")
	return b.String()
}
