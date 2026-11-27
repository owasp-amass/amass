// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// LensThirdParty asks for the outside parties that the subject's controlled
// assets depend on (registrars, DNS and hosting networks, certificate
// authorities, service providers, software). Which relationships are
// dependencies, and who controls the assets they reach, both come from the
// relationship semantics table, so new OAM types and relationships take
// part once they are annotated. The answer is built in Go and never
// reaches the model.
const LensThirdParty = "third_party"

// VendorUse is one outside party and the controlled assets that depend on
// it. Kind is "<Purpose>: <types>" from the semantics table: the purpose of
// the dependency relationship and the type of asset depended on.
type VendorUse struct {
	Vendor   string   `json:"vendor"`
	VendorID string   `json:"vendor_id,omitempty"`
	Kind     string   `json:"kind"`
	Via      string   `json:"via"`
	Assets   int      `json:"assets"`
	Examples []string `json:"examples"`
	// Witness holds the stored edges behind the first example: from the
	// controlled asset to the dependency and on to the party behind it.
	Witness []graph.WitnessEdge `json:"witness,omitempty"`
	// seen holds every asset counted in Assets, beyond the few examples.
	seen map[string]bool
}

// partyKey reduces a vendor name to the form compared when uses are
// grouped. A party with no stored organization is named by its registrable
// domain (dnsmadeeasy.com) and the same party's organization by its name
// (DNSMadeEasy), so a domain is keyed by the label before its public
// suffix and a name by its brand without spaces or punctuation.
func partyKey(name string) string {
	s := semantics.OrgNameKey(name)
	if graph.DomainName.MatchString(name) {
		s, _, _ = strings.Cut(graph.RegisteredDomain(name), ".")
	}

	key := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}

		return -1
	}, s)
	if key == "" {
		return strings.ToLower(name)
	}

	return key
}

// ThirdPartyReport is the result of the third-party lens.
type ThirdPartyReport struct {
	Root           graph.Asset    `json:"root"`
	Owners         []string       `json:"owners,omitempty"`
	Footprint      int            `json:"footprint"`
	FootprintTypes map[string]int `json:"footprint_types"`
	// SummarizedAddresses counts member addresses of held netblocks that host
	// no name or service and were summarized rather than kept in the footprint
	// (see lensWalker.summarizeBareAddrs).
	SummarizedAddresses int `json:"summarized_addresses,omitempty"`
	// SkippedURLs counts URLs under the footprint's host names left out by a
	// lens that does not read URLs (see lensWalker.skipHostedURLs).
	SkippedURLs int         `json:"skipped_urls,omitempty"`
	Vendors     []VendorUse `json:"vendors"`
	Reads       int         `json:"reads"`
	Truncated   bool        `json:"truncated"`
	Reason      string      `json:"reason,omitempty"`
	// UnrecognizedSPF and UnrecognizedTokens are set by the vendors lens: the
	// domain's SPF includes no vendor entry matches, and the keys of its
	// verification-like TXT records no DNS-SD prefix recognizes.
	UnrecognizedSPF    []string `json:"unrecognized_spf,omitempty"`
	UnrecognizedTokens []string `json:"unrecognized_tokens,omitempty"`
	// Institution, InstitutionOwn, Affiliates and Hosted are set by the
	// vendors lens from the family lens: the domain's main organization, and
	// the uses moved out of Vendors because they are the institution's own,
	// an affiliate's, or domains the institution's networks host for others.
	// FamilyNote says why the family lens was not applied.
	Institution    string      `json:"institution,omitempty"`
	InstitutionOwn []VendorUse `json:"institution_own,omitempty"`
	Affiliates     []VendorUse `json:"affiliates,omitempty"`
	Hosted         []VendorUse `json:"hosted,omitempty"`
	FamilyNote     string      `json:"family_note,omitempty"`
}

// vendorSet accumulates vendor uses keyed by vendor and kind.
type vendorSet map[string]*VendorUse

func (v vendorSet) add(name, id, kind, via string, user graph.Asset, witness []graph.WitnessEdge) {
	if name == "" {
		return
	}

	key := kind + "\x00" + partyKey(name)
	use, ok := v[key]
	if !ok {
		use = &VendorUse{Vendor: name, VendorID: id, Kind: kind, Via: via, Examples: []string{}, Witness: witness,
			seen: map[string]bool{}}
		v[key] = use
	} else if use.VendorID == "" && id != "" && !graph.DomainName.MatchString(name) {
		// The same party reached through a stored organization: name it by
		// that organization rather than by its domain.
		use.Vendor, use.VendorID, use.Witness = name, id, witness
	}

	example := graph.AssetLabel(user)
	if use.seen[example] {
		return
	}

	use.seen[example] = true
	use.Assets++
	if len(use.Examples) < lensMaxExamples {
		use.Examples = append(use.Examples, example)
	}
}

// SearchThirdParties runs the third-party lens from root within the
// default limits.
func SearchThirdParties(ctx context.Context, graph graph.Graph, schema graph.SchemaCatalog, root graph.Asset) (ThirdPartyReport, error) {
	return SearchThirdPartiesWithin(ctx, graph, schema, root, LensLimits{})
}

// SearchThirdPartiesWithin runs the third-party lens from root within
// limits.
func SearchThirdPartiesWithin(ctx context.Context, graph graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (ThirdPartyReport, error) {
	return searchThirdPartiesScoped(ctx, graph, schema, root, limits, nil, nil)
}

// searchThirdPartiesScoped is searchThirdPartiesWithin that does not follow
// controls edges into the organizations in stopAt, and does not scan the
// dependencies of controlled assets already in scanned (another scope's),
// adding its own to it.
func searchThirdPartiesScoped(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits, stopAt, scanned map[string]bool) (ThirdPartyReport, error) {
	report := ThirdPartyReport{Root: root, FootprintTypes: map[string]int{}, Vendors: []VendorUse{}}
	meaning := graph.MeaningsOf(schema)
	if schema == nil || meaning == nil {
		return report, errors.New("the third-party lens requires relationship semantics")
	}

	bounded, ok := g.(graph.BoundedGraph)
	if !ok {
		return report, errors.New("bounded graph reader required")
	}

	if err := limits.Validate(); err != nil {
		return report, err
	}

	w := newLensWalker(ctx, g, bounded, meaning, schema.Relations(), root, &report)
	w.limit(limits)
	w.stopAt = stopAt
	roots := []graph.Asset{root}
	owners, err := w.owningOrganizations(root)
	if err != nil {
		return report, err
	}
	for _, o := range owners {
		if stopAt[o.ID] {
			// Scanned on its own in a group rollup.
			continue
		}
		report.Owners = append(report.Owners, graph.AssetLabel(o))
		roots = append(roots, o)
	}

	w.controllers = map[string]controller{}
	owned, order, err := w.controlledFootprint(roots)
	if err != nil {
		return report, err
	}

	report.Footprint = len(owned)
	ownDomains := map[string]bool{}
	var ownNets []netip.Prefix
	for _, a := range owned {
		report.FootprintTypes[a.Type]++
		switch a.Type {
		case "FQDN":
			ownDomains[graph.RegisteredDomain(graph.FQDNName(a))] = true
		case "Netblock":
			if p, err := netip.ParsePrefix(graph.ContentString(a, "cidr")); err == nil {
				ownNets = append(ownNets, p.Masked())
			}
		}
	}

	vendors := vendorSet{}
	d := dependencyScan{w: w, owned: owned, ownDomains: ownDomains, ownNets: ownNets, vendors: vendors,
		pending: new([]dependency)}
	for _, id := range order {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if w.outOfReads() {
			w.truncate("database read limit")
			break
		}
		if scanned != nil {
			if scanned[id] {
				continue
			}
			scanned[id] = true
		}
		if err := d.scan(owned[id]); err != nil {
			return report, err
		}
		if d.queued() >= dependencyBatch {
			if err := d.resolve(); err != nil {
				return report, err
			}
		}
	}
	if err := d.resolve(); err != nil {
		return report, err
	}

	totals := map[string]int{}
	for _, use := range vendors {
		report.Vendors = append(report.Vendors, *use)
		totals[use.Kind] += use.Assets
	}

	sort.Slice(report.Vendors, func(i, j int) bool {
		a, b := report.Vendors[i], report.Vendors[j]
		if a.Kind != b.Kind {
			if totals[a.Kind] != totals[b.Kind] {
				return totals[a.Kind] > totals[b.Kind]
			}

			return a.Kind < b.Kind
		}
		if a.Assets != b.Assets {
			return a.Assets > b.Assets
		}

		return a.Vendor < b.Vendor
	})
	return report, nil
}

// UnattributedAddresses names the party behind public addresses with no
// stored network, autonomous system or organization.
const UnattributedAddresses = "IP addresses with no recorded network owner"

// PrivateAddresses is the hosting party of names that resolve to private or
// reserved addresses: they point inside some network, at no provider.
const PrivateAddresses = "private or reserved addresses"

// dependencyKind names a vendor group from the semantics table: the purpose
// of the dependency relationship and the type of asset depended on, such as
// "DNS: IP addresses" or "Certificate: contact records".
func dependencyKind(purpose, kind string) string {
	title := "Other"
	switch {
	case purpose == "":
	case len(purpose) <= 3:
		title = strings.ToUpper(purpose)
	default:
		title = strings.ToUpper(purpose[:1]) + purpose[1:]
	}

	return title + ": " + typePlural(kind)
}

// typePlural renders an OAM type name as plural words, keeping acronyms
// ("IPAddress" to "IP addresses", "FQDN" to "FQDNs").
func typePlural(kind string) string {
	words := strings.Fields(graph.CamelBoundary1.ReplaceAllString(graph.CamelBoundary2.ReplaceAllString(kind,
		"$1 $2"), "$1 $2"))
	for i, w := range words {
		if strings.ToUpper(w) != w {
			words[i] = strings.ToLower(w)
		}
	}
	if n := len(words); n > 0 {
		last := words[n-1]
		switch {
		case strings.ToUpper(last) == last:
			words[n-1] = last + "s"
		case strings.HasSuffix(last, "y"):
			words[n-1] = strings.TrimSuffix(last, "y") + "ies"
		case strings.HasSuffix(last, "s"):
			words[n-1] = last + "es"
		default:
			words[n-1] = last + "s"
		}
	}

	return strings.Join(words, " ")
}

// ThirdPartyAnswer renders a ThirdPartyReport as plain text.
func ThirdPartyAnswer(r ThirdPartyReport) string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root) + " (" + r.Root.Type + ")"
	if r.Footprint <= 1 {
		fmt.Fprintf(&b, "No assets are documented as controlled by %s: the Asset Database has no registrant, "+
			"contact, website or subsidiary relationships that attribute assets to it, so its third-party vendors "+
			"cannot be identified. Collecting registration (WHOIS/RDAP) data for its domains and networks would "+
			"provide them.", subject)
		return b.String()
	}

	types := make([]string, 0, len(r.FootprintTypes))
	for t, n := range r.FootprintTypes {
		types = append(types, fmt.Sprintf("%d %s", n, t))
	}

	sort.Strings(types)
	fmt.Fprintf(&b, "Third-party vendors used by %s, from %d controlled asset(s) (%s)", subject, r.Footprint,
		strings.Join(types, ", "))
	if len(r.Owners) > 0 {
		fmt.Fprintf(&b, " including those of its registrant %s", strings.Join(r.Owners, ", "))
	} else if r.Root.Type != "Organization" {
		b.WriteString(" (no owning organization is documented for it, so only its own records are included)")
	}

	b.WriteString(":\n")
	if len(r.Vendors) == 0 {
		b.WriteString("No outside registrars, DNS hosts, certificate authorities, hosting networks or service " +
			"providers are recorded for these assets.\n")
	}

	kind := ""
	for _, v := range r.Vendors {
		if v.Kind != kind {
			kind = v.Kind
			fmt.Fprintf(&b, "%s:\n", kind)
		}

		if v.Kind == KindDocument {
			fmt.Fprintf(&b, "  %s: %d document(s): %s\n", v.Vendor, v.Assets, strings.Join(v.Examples, "; "))
			continue
		}
		fmt.Fprintf(&b, "  %s: %d asset(s), e.g. %s\n", v.Vendor, v.Assets, strings.Join(v.Examples, ", "))
	}

	b.WriteString("These are stored OAM relationships, not verified contracts or current service use.")
	if r.Truncated {
		b.WriteString(" Results are partial (" + r.Reason + "); additional vendors may exist.")
	}

	return b.String()
}

// VendorQuestion matches explicit vendor questions such as "Which
// third-party vendors are being used by the OWASP Foundation
// organization?" or "List the vendors of example.com". The subject is the
// captured name.
var VendorQuestion = regexp.MustCompile(`(?i)^\s*(?:(?:which|what|who)(?:\s+(?:are|is))?|list|show|name)\s+(?:all\s+)?(?:of\s+)?(?:the\s+)?(?:third[- ]party\s+|external\s+|outside\s+)?(?:vendors|suppliers|providers|service providers|services|third[- ]parties)\s+(?:(?:(?:are|is)\s+)?(?:being\s+|currently\s+)?(?:used|relied (?:on|upon)|depended (?:on|upon)|engaged)\s+by|(?:of|for))\s+(?:the\s+)?(.+?)\s*\??\s*$`)
