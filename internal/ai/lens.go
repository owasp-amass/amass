// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/owasp-amass/amass/v5/internal/ai/semantics"
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
	Witness []WitnessEdge `json:"witness,omitempty"`
	// seen holds every asset counted in Assets, beyond the few examples.
	seen map[string]bool
}

// partyKey reduces a vendor name to the form compared when uses are
// grouped. A party with no stored organization is named by its registrable
// domain (dnsmadeeasy.com) and the same party's organization by its name
// (DNSMadeEasy), so a domain is keyed by the label before its public
// suffix and a name by its brand without spaces or punctuation.
func partyKey(name string) string {
	s := brandName(name)
	if domainName.MatchString(name) {
		s, _, _ = strings.Cut(registeredDomain(name), ".")
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
	Root           Asset          `json:"root"`
	Owners         []string       `json:"owners,omitempty"`
	Footprint      int            `json:"footprint"`
	FootprintTypes map[string]int `json:"footprint_types"`
	Vendors        []VendorUse    `json:"vendors"`
	Reads          int            `json:"reads"`
	Truncated      bool           `json:"truncated"`
	Reason         string         `json:"reason,omitempty"`
	// UnrecognizedSPF and UnrecognizedTokens are set by the vendors lens: the
	// domain's SPF includes no vendor entry matches, and the keys of its
	// verification-like TXT records no DNS-SD prefix recognizes.
	UnrecognizedSPF    []string `json:"unrecognized_spf,omitempty"`
	UnrecognizedTokens []string `json:"unrecognized_tokens,omitempty"`
	// Institution, InstitutionOwn and Affiliates are set by the vendors lens
	// from the family lens: the domain's main organization, and the uses
	// moved out of Vendors because they are the institution's own or an
	// affiliate's. FamilyNote says why the family lens was not applied.
	Institution    string      `json:"institution,omitempty"`
	InstitutionOwn []VendorUse `json:"institution_own,omitempty"`
	Affiliates     []VendorUse `json:"affiliates,omitempty"`
	FamilyNote     string      `json:"family_note,omitempty"`
}

// vendorSet accumulates vendor uses keyed by vendor and kind.
type vendorSet map[string]*VendorUse

func (v vendorSet) add(name, id, kind, via string, user Asset, witness []WitnessEdge) {
	if name == "" {
		return
	}

	key := kind + "\x00" + partyKey(name)
	use, ok := v[key]
	if !ok {
		use = &VendorUse{Vendor: name, VendorID: id, Kind: kind, Via: via, Examples: []string{}, Witness: witness,
			seen: map[string]bool{}}
		v[key] = use
	} else if use.VendorID == "" && id != "" && !domainName.MatchString(name) {
		// The same party reached through a stored organization: name it by
		// that organization rather than by its domain.
		use.Vendor, use.VendorID, use.Witness = name, id, witness
	}

	example := assetLabel(user)
	if use.seen[example] {
		return
	}

	use.seen[example] = true
	use.Assets++
	if len(use.Examples) < lensMaxExamples {
		use.Examples = append(use.Examples, example)
	}
}

// searchThirdParties runs the third-party lens from root within the
// default limits.
func searchThirdParties(ctx context.Context, graph Graph, schema SchemaCatalog, root Asset) (ThirdPartyReport, error) {
	return searchThirdPartiesWithin(ctx, graph, schema, root, LensLimits{})
}

// searchThirdPartiesWithin runs the third-party lens from root within
// limits.
func searchThirdPartiesWithin(ctx context.Context, graph Graph, schema SchemaCatalog, root Asset,
	limits LensLimits) (ThirdPartyReport, error) {
	report := ThirdPartyReport{Root: root, FootprintTypes: map[string]int{}, Vendors: []VendorUse{}}
	meaning := meaningsOf(schema)
	if schema == nil || meaning == nil {
		return report, errors.New("the third-party lens requires relationship semantics")
	}

	bounded, ok := graph.(BoundedGraph)
	if !ok {
		return report, errors.New("bounded graph reader required")
	}

	if err := limits.Validate(); err != nil {
		return report, err
	}

	w := newLensWalker(ctx, graph, bounded, meaning, schema.Relations(), root, &report)
	w.maxAssets, w.maxReads = limits.assets(), limits.reads()
	roots := []Asset{root}
	owners, err := w.owningOrganizations(root)
	if err != nil {
		return report, err
	}
	for _, o := range owners {
		report.Owners = append(report.Owners, assetLabel(o))
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
			ownDomains[registeredDomain(fqdnName(a))] = true
		case "Netblock":
			if p, err := netip.ParsePrefix(contentString(a, "cidr")); err == nil {
				ownNets = append(ownNets, p.Masked())
			}
		}
	}

	vendors := vendorSet{}
	d := dependencyScan{w: w, owned: owned, ownDomains: ownDomains, ownNets: ownNets, vendors: vendors}
	for _, id := range order {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if report.Reads >= w.maxReads {
			w.truncate("database read limit")
			break
		}
		if err := d.scan(owned[id]); err != nil {
			return report, err
		}
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

// dependencyScan finds the outside parties that controlled assets depend
// on. Every rule comes from the semantics table:
//   - a third_party edge marked as a vendor names a dependency directly;
//   - an infrastructure edge names a dependency on the asset it reaches,
//     whose own vendor third_party edges are dependencies too (a service's
//     provider and software);
//   - a shared edge into a controlled asset (a certificate listing a
//     controlled name) is not a dependency itself, but its vendor
//     third_party edges are (the certificate's issuer).
//
// The party behind a dependency is whoever controls it (see party).
type dependencyScan struct {
	w          *lensWalker
	owned      map[string]Asset
	ownDomains map[string]bool
	// ownNets are the footprint's netblocks: an address in one is
	// controlled even when no stored relationship says so.
	ownNets []netip.Prefix
	vendors vendorSet
	// self names the subject in table cells it controls.
	self string
}

func (d dependencyScan) scan(cur Asset) error {
	steps, err := d.w.steps(cur)
	if err != nil {
		return err
	}
	for _, s := range steps {
		if _, mine := d.owned[s.other.ID]; mine {
			continue
		}

		via := cur.Type + " " + s.edge.Label
		hop := []WitnessEdge{witnessOf(s.edge, cur, s.other)}
		switch {
		case s.attr == attrThirdParty && s.forward && s.vendor:
			if err := d.depend(cur, cur, s, via, nil); err != nil {
				return err
			}
		case s.attr == attrInfrastructure && s.forward:
			if err := d.depend(cur, cur, s, via, nil); err != nil {
				return err
			}
			if err := d.through(cur, s.other, via, hop); err != nil {
				return err
			}
		case s.attr == attrShared && !s.forward:
			if err := d.through(cur, s.other, s.other.Type, hop); err != nil {
				return err
			}
		}
	}

	return nil
}

// through records the vendor dependencies of an intermediate asset on
// behalf of the controlled asset cur.
func (d dependencyScan) through(cur, mid Asset, via string, prefix []WitnessEdge) error {
	steps, err := d.w.steps(mid)
	if err != nil {
		return err
	}
	for _, s := range steps {
		if _, mine := d.owned[s.other.ID]; mine || s.attr != attrThirdParty || !s.forward || !s.vendor {
			continue
		}
		if err := d.depend(cur, mid, s, via+" "+mid.Type+" "+s.edge.Label, prefix); err != nil {
			return err
		}
	}

	return nil
}

// depend records the party controlling s.other as a vendor of cur; s is a
// step from from (cur, or an intermediate asset reached through prefix).
func (d dependencyScan) depend(cur, from Asset, s step, via string, prefix []WitnessEdge) error {
	name, id, own, witness, err := d.party(s.other)
	if err != nil || own || name == "" {
		return err
	}

	chain := append(append(append([]WitnessEdge(nil), prefix...), witnessOf(s.edge, from, s.other)), witness...)
	d.vendors.add(name, id, dependencyKind(s.purpose, s.other.Type), via, cur, chain)
	return nil
}

// party names whoever controls a: the closest Organization along
// ownerPass; otherwise the operator of a network carrying it (an incoming
// infrastructure edge with purpose network, such as an autonomous system
// announcing its netblock); otherwise the most registration-like asset
// reached. own is set when control leads back to the footprint.
func (d dependencyScan) party(a Asset) (string, string, bool, []WitnessEdge, error) {
	c, err := d.w.controllerOf(a, d.owned)
	if err != nil {
		return "", "", false, nil, err
	}
	if c.own {
		return "", "", true, c.witness(c.visited[len(c.visited)-1].ID, d.w.assets), nil
	}
	if org, ok := namedOrganization(c.orgs); ok {
		_, own := d.owned[org.ID]
		return assetLabel(org), org.ID, own, c.witness(org.ID, d.w.assets), nil
	}
	for _, v := range c.visited {
		steps, err := d.w.steps(v)
		if err != nil {
			return "", "", false, nil, err
		}
		for _, s := range steps {
			if s.forward || s.attr != attrInfrastructure || s.purpose != "network" {
				continue
			}
			if _, mine := d.owned[s.other.ID]; mine {
				return "", "", true, nil, nil
			}

			oc, err := d.w.controllerOf(s.other, d.owned)
			if err != nil || oc.own {
				return "", "", oc.own, nil, err
			}

			base := append(c.witness(v.ID, d.w.assets), witnessOf(s.edge, v, s.other))
			if org, ok := namedOrganization(oc.orgs); ok {
				return assetLabel(org), org.ID, false, append(base, oc.witness(org.ID, d.w.assets)...), nil
			}

			name, id, own, best, err := d.fallbackName(oc.visited)
			return name, id, own, append(base, oc.witness(best, d.w.assets)...), err
		}
	}

	name, id, own, best, err := d.fallbackName(c.visited)
	return name, id, own, c.witness(best, d.w.assets), err
}

// namedOrganization returns the closest organization whose name identifies
// someone. Organizations stored before a placeholder such as "domain admin"
// was refused are skipped, so the party is named by what lies behind them.
func namedOrganization(orgs []Asset) (Asset, bool) {
	for _, o := range orgs {
		if !semantics.IsPlaceholderOrganization(assetLabel(o)) {
			return o, true
		}
	}

	return Asset{}, false
}

// fallbackName names a party with no documented Organization by the
// visited asset closest to one (a registration record before the address
// it registers). FQDNs are named by their registrable domain, and a domain
// of the footprint counts as controlled.
func (d dependencyScan) fallbackName(visited []Asset) (string, string, bool, string, error) {
	if len(visited) == 0 {
		return "", "", false, "", nil
	}

	best := visited[0]
	for _, v := range visited[1:] {
		dv, okv := d.w.ownerDist[v.Type]
		db, okb := d.w.ownerDist[best.Type]
		if okv && (!okb || dv < db || (dv == db && len(assetLabel(v)) < len(assetLabel(best)))) {
			best = v
		}
	}
	switch best.Type {
	case "FQDN":
		domain := registeredDomain(fqdnName(best))
		if reverseZone(domain) {
			// An address's pointer name says nothing about who operates it.
			return "", "", false, best.ID, nil
		}

		return vendorNameOf(domain), "", d.ownDomains[domain], best.ID, nil
	case "IPAddress":
		addr, err := netip.ParseAddr(assetLabel(best))
		if err != nil {
			break
		}
		addr = addr.Unmap()
		if !addr.IsGlobalUnicast() || addr.IsPrivate() {
			// Private and reserved addresses name no outside party.
			return "", "", false, best.ID, nil
		}
		for _, p := range d.ownNets {
			if p.Contains(addr) {
				return "", "", true, best.ID, nil
			}
		}

		// No network or organization is stored for the address, so who
		// operates it is unknown; the addresses are reported together.
		return unattributedAddresses, "", false, best.ID, nil
	}

	return assetLabel(best), best.ID, false, best.ID, nil
}

// unattributedAddresses names the party behind public addresses with no
// stored network, autonomous system or organization.
const unattributedAddresses = "IP addresses with no recorded network owner"

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
	words := strings.Fields(camelBoundary1.ReplaceAllString(camelBoundary2.ReplaceAllString(kind, "$1 $2"), "$1 $2"))
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

// thirdPartyAnswer renders a ThirdPartyReport as plain text.
func thirdPartyAnswer(r ThirdPartyReport) string {
	var b strings.Builder
	subject := assetLabel(r.Root) + " (" + r.Root.Type + ")"
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

		fmt.Fprintf(&b, "  %s: %d asset(s), e.g. %s\n", v.Vendor, v.Assets, strings.Join(v.Examples, ", "))
	}

	b.WriteString("These are stored OAM relationships, not verified contracts or current service use.")
	if r.Truncated {
		b.WriteString(" Results are partial (" + r.Reason + "); additional vendors may exist.")
	}

	return b.String()
}

// assetLabel is the human name of an asset without its ID.
func assetLabel(a Asset) string {
	if v := contentString(a, "name", "legal_name", "url", "subject_common_name", "cidr", "address", "number",
		"handle", "service_type"); v != "" {
		return v
	}

	return a.Key
}

// contentString returns the first non-empty string or number content field.
func contentString(a Asset, keys ...string) string {
	data, err := json.Marshal(a.Content)
	if err != nil {
		return ""
	}

	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return ""
	}
	for _, key := range keys {
		raw, ok := fields[key]
		if !ok {
			continue
		}

		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return s
		}

		var n json.Number
		if json.Unmarshal(raw, &n) == nil && n != "" && n != "0" {
			return n.String()
		}
	}

	return ""
}

func fqdnName(a Asset) string {
	name := contentString(a, "name")
	if name == "" {
		name = a.Key
	}

	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// registeredDomain approximates the registrable domain of name: the last two
// labels, or three under a two-letter country code with a generic second
// level (example.co.uk).
func registeredDomain(name string) string {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".")
	n := len(labels)
	if n <= 2 {
		return strings.Join(labels, ".")
	}

	switch labels[n-2] {
	case "co", "com", "net", "org", "ac", "gov", "edu", "ne", "or", "go":
		if len(labels[n-1]) == 2 {
			return strings.Join(labels[n-3:], ".")
		}
	}

	return strings.Join(labels[n-2:], ".")
}

// vendorQuestion matches explicit vendor questions such as "Which
// third-party vendors are being used by the Colgate University
// organization?" or "List the vendors of example.com". The subject is the
// captured name.
var vendorQuestion = regexp.MustCompile(`(?i)^\s*(?:(?:which|what|who)(?:\s+(?:are|is))?|list|show|name)\s+(?:all\s+)?(?:of\s+)?(?:the\s+)?(?:third[- ]party\s+|external\s+|outside\s+)?(?:vendors|suppliers|providers|service providers|services|third[- ]parties)\s+(?:(?:(?:are|is)\s+)?(?:being\s+|currently\s+)?(?:used|relied (?:on|upon)|depended (?:on|upon)|engaged)\s+by|(?:of|for))\s+(?:the\s+)?(.+?)\s*\??\s*$`)

var domainName = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$`)

// deterministicThirdPartyQuery compiles an explicit vendor question about
// a named organization or domain.
func deterministicThirdPartyQuery(question string) (Query, bool) {
	m := vendorQuestion.FindStringSubmatch(question)
	if len(m) != 2 {
		return Query{}, false
	}

	name := strings.TrimSpace(m[1])
	name = strings.TrimSuffix(strings.TrimSuffix(name, "'s"), "’s")
	for _, suffix := range []string{" organization", " organisation", " company"} {
		if len(name) > len(suffix) && strings.EqualFold(name[len(name)-len(suffix):], suffix) {
			name = strings.TrimSpace(name[:len(name)-len(suffix)])
		}
	}
	if name == "" || len(name) > 200 || strings.ContainsAny(name, "?;") {
		return Query{}, false
	}

	subject := PlanSubject{Type: "Organization", Name: name}
	if domainName.MatchString(name) {
		subject = PlanSubject{Type: "FQDN", Field: "name", Value: strings.ToLower(name)}
	}

	return thirdPartyQuery(question, subject, SourceThirdPartyLens), true
}

func thirdPartyQuery(question string, subject PlanSubject, source string) Query {
	return Query{
		Version:   QueryVersion,
		Question:  question,
		Subject:   subject,
		Traversal: TraversalExplore,
		Direction: "both",
		Purpose:   "connected",
		Lens:      LensThirdParty,
		Source:    source,
	}
}
