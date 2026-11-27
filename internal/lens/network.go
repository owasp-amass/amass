// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// LensNetwork asks for the network infrastructure of a domain or
// organization: the address space and autonomous systems it holds, where
// its names resolve, what is inside its own space, and what does not fit.
// The answer is built in Go; nothing is written.
const LensNetwork = "network"

// OwnNetwork is a netblock the subject holds.
type OwnNetwork struct {
	CIDR    string `json:"cidr"`
	ID      string `json:"id"`
	Version int    `json:"version"`
	// Names counts the subject's names resolving into the network,
	// Addresses the subject's addresses stored inside it and Services the
	// services stored on those addresses.
	Names     int      `json:"names"`
	Addresses int      `json:"addresses"`
	Services  int      `json:"services"`
	Announced []string `json:"announced_by,omitempty"`
}

// OwnAS is an autonomous system the subject holds.
type OwnAS struct {
	Number string `json:"number"`
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	// Announces are the prefixes the AS announces; Foreign those not among
	// the subject's netblocks, such as a customer's or a provider's space.
	Announces []string `json:"announces"`
	Foreign   []string `json:"foreign,omitempty"`
}

// ForeignNames are the names of another domain found on addresses in the
// subject's own netblocks: a tenant, a partner or something left behind.
type ForeignNames struct {
	Domain    string   `json:"domain"`
	Names     int      `json:"names"`
	Addresses []string `json:"addresses"`
	Examples  []string `json:"examples"`
}

// HostingShare is where some of the subject's names resolve.
type HostingShare struct {
	Party    string   `json:"party"`
	PartyID  string   `json:"party_id,omitempty"`
	Own      bool     `json:"own,omitempty"`
	Names    int      `json:"names"`
	Networks []string `json:"networks,omitempty"`
	Examples []string `json:"examples,omitempty"`
	// Regions and Services are the cloud regions and services the provider's
	// range feed published for the networks hosting these names, when the
	// party is a cloud or CDN provider.
	Regions  []string `json:"regions,omitempty"`
	Services []string `json:"services,omitempty"`
}

// NetworkReport is the result of the network infrastructure lens.
type NetworkReport struct {
	Root      graph.Asset    `json:"root"`
	Owners    []string       `json:"owners,omitempty"`
	Footprint int            `json:"footprint"`
	Networks  []OwnNetwork   `json:"networks"`
	ASNs      []OwnAS        `json:"asns"`
	Hosting   []HostingShare `json:"hosting"`
	// Resolved counts the subject's names with a stored address or an
	// alias (CNAME) to another name, Aliased those reached through an
	// alias, and Unresolved those with neither.
	Resolved   int `json:"resolved"`
	Aliased    int `json:"aliased"`
	Unresolved int `json:"unresolved"`
	// Unused are the subject's netblocks no name of the subject resolves
	// into.
	Unused []string `json:"unused,omitempty"`
	// Foreign are other domains' names on addresses in the subject's
	// netblocks, by an address record or a pointer record.
	Foreign   []ForeignNames `json:"foreign,omitempty"`
	Reads     int            `json:"reads"`
	Truncated bool           `json:"truncated"`
	Reason    string         `json:"reason,omitempty"`
}

// netHostingExamples bounds the example names per hosting party.
const netHostingExamples = 3

// FindNetworkInfrastructure walks the controlled footprint of a domain or
// organization, as the vendors lens does, and reports the netblocks and
// autonomous systems it holds, where its names resolve (its own space or a
// provider's), what is stored inside its own space, and its netblocks no
// name uses. It reads only.
func FindNetworkInfrastructure(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (NetworkReport, error) {
	out := NetworkReport{Root: root}
	meaning := graph.MeaningsOf(schema)
	if schema == nil || meaning == nil {
		return out, errors.New("the network lens requires relationship semantics")
	}
	bounded, ok := g.(graph.BoundedGraph)
	if !ok {
		return out, errors.New("bounded graph reader required")
	}
	if err := limits.Validate(); err != nil {
		return out, err
	}

	report := ThirdPartyReport{Root: root, FootprintTypes: map[string]int{}}
	w := newLensWalker(ctx, g, bounded, meaning, schema.Relations(), root, &report)
	w.limit(limits)
	roots := []graph.Asset{root}
	owners, err := w.owningOrganizations(root)
	if err != nil {
		return out, err
	}
	for _, o := range owners {
		out.Owners = append(out.Owners, graph.AssetLabel(o))
		roots = append(roots, o)
	}

	owned, order, err := w.controlledFootprint(roots)
	if err != nil {
		return out, err
	}
	out.Footprint = len(owned)

	n := networkScan{w: w, owned: owned, nets: map[string]*OwnNetwork{}, hosting: map[string]*HostingShare{},
		blockNames: map[string]map[string]bool{}}
	n.d = dependencyScan{w: w, owned: owned, ownDomains: map[string]bool{}}
	for _, id := range order {
		a := owned[id]
		switch a.Type {
		case "Netblock":
			n.addNetwork(a)
		case "FQDN":
			n.d.ownDomains[graph.RegisteredDomain(graph.FQDNName(a))] = true
		}
	}
	for _, net := range n.nets {
		if p, err := netip.ParsePrefix(net.CIDR); err == nil {
			n.d.ownNets = append(n.d.ownNets, p.Masked())
		}
	}

	// The subject's own names and systems come first; the contents of its
	// netblocks, which can be large, take what the read budget leaves.
	for pass := 0; pass < 2; pass++ {
		for _, id := range order {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			if w.outOfReads() {
				w.truncate("database read limit")
				break
			}

			a := owned[id]
			var err error
			switch {
			case pass == 0 && a.Type == "FQDN":
				err = n.resolve(a, &out)
			case pass == 0 && a.Type == "IPAddress":
				err = n.inside(a)
			case pass == 0 && a.Type == "AutonomousSystem":
				err = n.autonomousSystem(a, &out)
			case pass == 1 && a.Type == "Netblock":
				err = n.contents(a)
			}
			if err != nil {
				return out, err
			}
		}
	}

	for _, net := range n.nets {
		net.Names = len(n.blockNames[net.ID])
		if net.Names == 0 {
			out.Unused = append(out.Unused, net.CIDR)
		}
		out.Networks = append(out.Networks, *net)
	}
	sort.Slice(out.Networks, func(i, j int) bool {
		a, b := out.Networks[i], out.Networks[j]
		if a.Names != b.Names {
			return a.Names > b.Names
		}
		return a.CIDR < b.CIDR
	})
	sort.Strings(out.Unused)
	for _, f := range n.foreign {
		sort.Strings(f.Addresses)
		out.Foreign = append(out.Foreign, *f)
	}
	sort.Slice(out.Foreign, func(i, j int) bool {
		a, b := out.Foreign[i], out.Foreign[j]
		if a.Names != b.Names {
			return a.Names > b.Names
		}
		return a.Domain < b.Domain
	})
	for _, h := range n.hosting {
		sort.Strings(h.Networks)
		sort.Strings(h.Regions)
		sort.Strings(h.Services)
		out.Hosting = append(out.Hosting, *h)
	}
	sort.Slice(out.Hosting, func(i, j int) bool {
		a, b := out.Hosting[i], out.Hosting[j]
		if a.Names != b.Names {
			return a.Names > b.Names
		}
		return a.Party < b.Party
	})
	sort.Slice(out.ASNs, func(i, j int) bool { return out.ASNs[i].Number < out.ASNs[j].Number })

	out.Reads = report.Reads
	out.Truncated, out.Reason = report.Truncated, report.Reason
	return out, nil
}

// FormatNetworkReport renders the network infrastructure lens for a
// terminal.
func FormatNetworkReport(r NetworkReport) string {
	var b strings.Builder
	scope := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		scope += " and " + strings.Join(r.Owners, ", ")
	}
	fmt.Fprintf(&b, "Network infrastructure of %s, from %d controlled asset(s) (%d reads).\n", scope, r.Footprint,
		r.Reads)

	v4, v6 := 0, 0
	for _, n := range r.Networks {
		if n.Version == 6 {
			v6++
		} else {
			v4++
		}
	}
	if len(r.Networks) == 0 && len(r.ASNs) == 0 {
		b.WriteString("No netblock or autonomous system registered to it is stored.\n")
	} else {
		fmt.Fprintf(&b, "\nIts own address space: %d IPv4 and %d IPv6 netblock(s)", v4, v6)
		if len(r.ASNs) > 0 {
			fmt.Fprintf(&b, ", %d autonomous system(s)", len(r.ASNs))
		}
		b.WriteString(".\n")
		for _, n := range r.Networks {
			fmt.Fprintf(&b, "  %s: %d of its names resolve here, %d address(es) stored, %d service(s)", n.CIDR,
				n.Names, n.Addresses, n.Services)
			if len(n.Announced) > 0 {
				fmt.Fprintf(&b, ", announced by %s", strings.Join(n.Announced, ", "))
			}
			b.WriteString("\n")
		}
		for _, a := range r.ASNs {
			fmt.Fprintf(&b, "  %s", a.Number)
			if a.Name != "" {
				fmt.Fprintf(&b, " (%s)", a.Name)
			}
			fmt.Fprintf(&b, " announces %d prefix(es)", len(a.Announces))
			if len(a.Foreign) > 0 {
				fmt.Fprintf(&b, ", %d of them not its own: %s", len(a.Foreign), strings.Join(a.Foreign, ", "))
			}
			b.WriteString("\n")
		}
	}

	if total := r.Resolved; total > 0 {
		fmt.Fprintf(&b, "\nWhere its %d resolving name(s) are hosted", total)
		if r.Aliased > 0 {
			fmt.Fprintf(&b, " (%d through an alias)", r.Aliased)
		}
		b.WriteString(":\n")
		for _, h := range r.Hosting {
			party := h.Party
			if h.Own {
				party = "its own networks"
			}
			fmt.Fprintf(&b, "  %s: %d (%.0f%%)", party, h.Names, 100*float64(h.Names)/float64(total))
			if len(h.Regions) > 0 {
				fmt.Fprintf(&b, " [%s]", strings.Join(h.Regions, ", "))
			}
			if len(h.Services) > 0 {
				fmt.Fprintf(&b, " (%s)", strings.Join(h.Services, ", "))
			}
			if len(h.Examples) > 0 {
				fmt.Fprintf(&b, ", e.g. %s", strings.Join(h.Examples, ", "))
			}
			b.WriteString("\n")
		}
	}
	if r.Unresolved > 0 {
		fmt.Fprintf(&b, "Names with no stored address: %d.\n", r.Unresolved)
	}

	if len(r.Unused) > 0 {
		fmt.Fprintf(&b, "\nNetblocks registered to it that none of its names use (%d): %s\n", len(r.Unused),
			strings.Join(r.Unused, ", "))
	}

	if len(r.Foreign) > 0 {
		fmt.Fprintf(&b, "\nNames of %d other domain(s) on addresses in its netblocks (tenants, partners or "+
			"leftovers):\n", len(r.Foreign))
		for _, f := range r.Foreign {
			fmt.Fprintf(&b, "  %s: %d name(s) on %s, e.g. %s\n", f.Domain, f.Names, strings.Join(f.Addresses, ", "),
				strings.Join(f.Examples, ", "))
		}
	}

	b.WriteString("These are stored registrations and resolutions, not a live scan.")
	if r.Truncated {
		fmt.Fprintf(&b, " Results are partial (%s)%s", r.Reason, partialAdvice(r.Reason))
	}
	b.WriteString("\n")
	return b.String()
}
