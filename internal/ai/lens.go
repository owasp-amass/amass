// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// LensThirdParty asks for the outside organizations and services that the
// subject's controlled assets depend on: registrars, DNS hosts, certificate
// authorities, hosting networks, CNAME targets, service providers and
// software. The answer is built in Go from the reviewed relationship
// attribution table and never reaches the model.
const LensThirdParty = "third_party"

// Third-party lens bounds. The walk never sends assets to a model, so these
// are database-cost limits rather than context limits.
const (
	lensMaxFootprint = 2000
	lensMaxPerAsset  = 500
	lensMaxReads     = 20000
	lensMaxExamples  = 3
)

// Vendor kinds, in the order the answer lists them.
var vendorKindOrder = []string{
	"Hosting and network providers",
	"DNS hosting",
	"DNS record targets (CNAME, NS, MX)",
	"Domain registrars",
	"Certificate authorities",
	"Service providers",
	"Software and products",
	"Domain verification",
	"Technical contacts",
	"Identity issuers",
	"Financial",
}

// vendorKinds maps a third_party relationship label to the kind of vendor
// it names. Labels missing here (abuse contacts, RDAP, WHOIS and OCSP
// endpoints, issuing certificates) name registry or protocol
// infrastructure rather than a vendor the subject chose, so they are not
// reported.
var vendorKinds = map[string]string{
	"registrar_contact":   "Domain registrars",
	"name_server":         "DNS hosting",
	"issuer_contact":      "Certificate authorities",
	"provider":            "Service providers",
	"product_used":        "Software and products",
	"verified_for":        "Domain verification",
	"technical_contact":   "Technical contacts",
	"issuing_agent":       "Identity issuers",
	"issuing_authority":   "Identity issuers",
	"registration_agency": "Identity issuers",
	"third_party":         "Financial",
}

// VendorUse is one outside party and the controlled assets that use it.
type VendorUse struct {
	Vendor   string   `json:"vendor"`
	VendorID string   `json:"vendor_id,omitempty"`
	Kind     string   `json:"kind"`
	Via      string   `json:"via"`
	Assets   int      `json:"assets"`
	Examples []string `json:"examples"`
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
}

// lensWalker reads the graph for one lens run, caching assets and edges and
// enforcing the read bounds.
type lensWalker struct {
	ctx     context.Context
	graph   Graph
	bounded BoundedGraph
	cat     AttributionCatalog
	assets  map[string]Asset
	edges   map[string][]Relation
	report  *ThirdPartyReport
	// expand, when set, limits which controlled asset types are expanded
	// further; other controlled assets are recorded but not read.
	expand map[string]bool
	// parent and via record how each controlled asset was reached, so a
	// witnessed path can be rebuilt from the root.
	parent map[string]string
	via    map[string]Relation
}

func (w *lensWalker) truncate(reason string) {
	if !w.report.Truncated {
		w.report.Truncated = true
		w.report.Reason = reason
	}
}

func (w *lensWalker) asset(id string) (Asset, error) {
	if a, ok := w.assets[id]; ok {
		return a, nil
	}

	a, err := w.graph.GetAsset(w.ctx, id)
	if err != nil {
		return Asset{}, err
	}

	w.assets[id] = a
	return a, nil
}

// neighbors returns the stored edges in both directions for id, read once.
func (w *lensWalker) neighbors(id string) ([]Relation, error) {
	if e, ok := w.edges[id]; ok {
		return e, nil
	}

	var all []Relation
	for _, dir := range []string{"out", "in"} {
		if w.report.Reads >= lensMaxReads {
			w.truncate("database read limit")
			break
		}

		w.report.Reads++
		edges, more, err := w.bounded.EdgesLimited(w.ctx, id, dir, "", time.Time{}, lensMaxPerAsset)
		if err != nil {
			return nil, err
		}
		if more {
			a := w.assets[id]
			w.truncate(fmt.Sprintf("more than %d %s edges on %s %s", lensMaxPerAsset, dir, a.Type, assetLabel(a)))
		}

		all = append(all, edges...)
	}

	w.edges[id] = all
	return all, nil
}

// step is one stored edge seen from the asset being expanded.
type step struct {
	edge    Relation
	other   Asset
	forward bool
	attr    string
}

func (w *lensWalker) steps(cur Asset) ([]step, error) {
	edges, err := w.neighbors(cur.ID)
	if err != nil {
		return nil, err
	}

	out := make([]step, 0, len(edges))
	for _, e := range edges {
		forward := e.FromID == cur.ID
		otherID := e.ToID
		if !forward {
			otherID = e.FromID
		}
		if otherID == "" || otherID == cur.ID {
			continue
		}

		other, err := w.asset(otherID)
		if err != nil {
			return nil, err
		}

		src, dst := cur.Type, other.Type
		if !forward {
			src, dst = other.Type, cur.Type
		}

		attr, ok := w.cat.Attribution(src, e.Label, e.Type, dst)
		if !ok {
			continue
		}

		out = append(out, step{edge: e, other: other, forward: forward, attr: attr})
	}

	return out, nil
}

// controlledFootprint collects the assets controlled by the roots: it
// follows same_subject edges (FQDN node edges only downward), controls
// edges forward and controller edges backward. It never enters another
// Organization except through controls (subsidiary, org_unit), and never
// expands a Person, so a shared contact cannot merge two footprints.
func (w *lensWalker) controlledFootprint(roots []Asset) (map[string]Asset, []string, error) {
	owned := map[string]Asset{}
	var order, queue []string
	for _, r := range roots {
		if _, ok := owned[r.ID]; !ok {
			owned[r.ID] = r
			order = append(order, r.ID)
			queue = append(queue, r.ID)
		}
	}

	for len(queue) > 0 {
		if err := w.ctx.Err(); err != nil {
			return nil, nil, err
		}
		if w.report.Reads >= lensMaxReads {
			w.truncate("database read limit")
			break
		}

		cur := owned[queue[0]]
		queue = queue[1:]
		if cur.Type == "Person" {
			continue
		}

		steps, err := w.steps(cur)
		if err != nil {
			return nil, nil, err
		}
		for _, s := range steps {
			if _, seen := owned[s.other.ID]; seen || s.other.Type == "Person" {
				continue
			}

			include := false
			switch s.attr {
			case attrSameSubject:
				include = s.other.Type != "Organization" && (s.edge.Label != "node" || s.forward)
			case attrControls:
				include = s.forward
			case attrController:
				include = !s.forward
			}
			if !include {
				continue
			}
			if len(owned) >= lensMaxFootprint {
				w.truncate("controlled asset limit")
				break
			}

			owned[s.other.ID] = s.other
			order = append(order, s.other.ID)
			if w.parent != nil {
				w.parent[s.other.ID] = cur.ID
				w.via[s.other.ID] = s.edge
			}
			if w.expand == nil || w.expand[s.other.Type] {
				queue = append(queue, s.other.ID)
			}
		}
	}

	return owned, order, nil
}

// owningOrganizations returns the Organizations documented as controlling
// an FQDN root through its domain registration, so that a domain question
// also covers the registrant's netblocks and certificates.
func (w *lensWalker) owningOrganizations(root Asset) ([]Asset, error) {
	if root.Type != "FQDN" {
		return nil, nil
	}

	var orgs []Asset
	seen := map[string]bool{}
	frontier := []Asset{root}
	for depth := 0; depth < 4 && len(frontier) > 0; depth++ {
		var next []Asset
		for _, cur := range frontier {
			steps, err := w.steps(cur)
			if err != nil {
				return nil, err
			}
			for _, s := range steps {
				if seen[s.other.ID] {
					continue
				}

				pass := (s.attr == attrSameSubject && s.edge.Label != "node") ||
					(s.attr == attrController && s.forward) || (s.attr == attrControls && !s.forward)
				if !pass {
					continue
				}

				seen[s.other.ID] = true
				if s.other.Type == "Organization" {
					orgs = append(orgs, s.other)
					continue
				}

				next = append(next, s.other)
			}
		}

		frontier = next
	}

	return orgs, nil
}

// party names the outside party behind a third_party target: an
// Organization, the Organization of a ContactRecord, the registered domain
// of an FQDN, a Product's manufacturer, or a Service.
func (w *lensWalker) party(target Asset) (string, string, error) {
	switch target.Type {
	case "Organization":
		return assetLabel(target), target.ID, nil
	case "ContactRecord", "Product", "ProductRelease":
		steps, err := w.steps(target)
		if err != nil {
			return "", "", err
		}
		for _, s := range steps {
			if s.forward && s.other.Type == "Organization" &&
				(s.edge.Label == "organization" || s.edge.Label == "manufacturer") {
				return assetLabel(s.other), s.other.ID, nil
			}
		}
		if target.Type != "ContactRecord" {
			return assetLabel(target), target.ID, nil
		}
	case "FQDN":
		return registeredDomain(fqdnName(target)), "", nil
	case "Service":
		return assetLabel(target), target.ID, nil
	}

	return "", "", nil
}

// network names the operator of the network holding an IP address: the
// registrant Organization of its netblock, or the name of the autonomous
// system announcing it. Owned netblocks return nothing.
func (w *lensWalker) network(ip Asset, owned map[string]Asset, cache map[string][2]string) (string, string, error) {
	steps, err := w.steps(ip)
	if err != nil {
		return "", "", err
	}
	for _, s := range steps {
		if s.forward || s.other.Type != "Netblock" || s.edge.Label != "contains" {
			continue
		}

		nb := s.other
		if _, ok := owned[nb.ID]; ok {
			return "", "", nil
		}
		if v, ok := cache[nb.ID]; ok {
			return v[0], v[1], nil
		}

		name, id, err := w.netblockOperator(nb, owned)
		if err != nil {
			return "", "", err
		}

		cache[nb.ID] = [2]string{name, id}
		return name, id, nil
	}

	return "", "", nil
}

func (w *lensWalker) netblockOperator(nb Asset, owned map[string]Asset) (string, string, error) {
	steps, err := w.steps(nb)
	if err != nil {
		return "", "", err
	}

	var asName, asID string
	for _, s := range steps {
		switch {
		case s.forward && s.edge.Label == "registration" && s.other.Type == "IPNetRecord":
			org, id, err := w.registrant(s.other)
			if err != nil {
				return "", "", err
			}
			if _, mine := owned[id]; mine && id != "" {
				return "", "", nil
			}
			if org != "" {
				return org, id, nil
			}
		case !s.forward && s.edge.Label == "announces" && s.other.Type == "AutonomousSystem":
			asName, asID, err = w.autonomousSystem(s.other)
			if err != nil {
				return "", "", err
			}
		}
	}

	return asName, asID, nil
}

// registrant returns the Organization behind a registration record's
// registrant contact.
func (w *lensWalker) registrant(record Asset) (string, string, error) {
	steps, err := w.steps(record)
	if err != nil {
		return "", "", err
	}
	for _, s := range steps {
		if s.forward && (s.edge.Label == "registrant" || s.edge.Label == "registrant_contact") &&
			s.other.Type == "ContactRecord" {
			return w.party(s.other)
		}
	}

	return "", "", nil
}

func (w *lensWalker) autonomousSystem(as Asset) (string, string, error) {
	label := "AS" + strings.TrimPrefix(assetLabel(as), "AS")
	steps, err := w.steps(as)
	if err != nil {
		return "", "", err
	}
	for _, s := range steps {
		if s.forward && s.edge.Label == "registration" && s.other.Type == "AutnumRecord" {
			if org, id, err := w.registrant(s.other); err != nil || org != "" {
				return org, id, err
			}
			if name := contentString(s.other, "name", "handle"); name != "" {
				return label + " " + name, as.ID, nil
			}
		}
	}

	return label, as.ID, nil
}

// vendorSet accumulates vendor uses keyed by vendor and kind.
type vendorSet map[string]*VendorUse

func (v vendorSet) add(name, id, kind, via string, user Asset) {
	if name == "" {
		return
	}

	key := kind + "\x00" + strings.ToLower(name)
	use, ok := v[key]
	if !ok {
		use = &VendorUse{Vendor: name, VendorID: id, Kind: kind, Via: via, Examples: []string{}}
		v[key] = use
	}

	example := assetLabel(user)
	for _, e := range use.Examples {
		if e == example {
			return
		}
	}

	use.Assets++
	if len(use.Examples) < lensMaxExamples {
		use.Examples = append(use.Examples, example)
	}
}

// searchThirdParties runs the third-party lens from root.
func searchThirdParties(ctx context.Context, graph Graph, cat AttributionCatalog, root Asset) (ThirdPartyReport, error) {
	report := ThirdPartyReport{Root: root, FootprintTypes: map[string]int{}, Vendors: []VendorUse{}}
	if cat == nil {
		return report, errors.New("the third-party lens requires relationship attribution semantics")
	}

	bounded, ok := graph.(BoundedGraph)
	if !ok {
		return report, errors.New("bounded graph reader required")
	}

	w := &lensWalker{ctx: ctx, graph: graph, bounded: bounded, cat: cat,
		assets: map[string]Asset{root.ID: root}, edges: map[string][]Relation{}, report: &report}
	roots := []Asset{root}
	owners, err := w.owningOrganizations(root)
	if err != nil {
		return report, err
	}
	for _, o := range owners {
		report.Owners = append(report.Owners, assetLabel(o))
		roots = append(roots, o)
	}

	owned, order, err := w.controlledFootprint(roots)
	if err != nil {
		return report, err
	}

	report.Footprint = len(owned)
	ownDomains := map[string]bool{}
	for _, a := range owned {
		report.FootprintTypes[a.Type]++
		if a.Type == "FQDN" {
			ownDomains[registeredDomain(fqdnName(a))] = true
		}
	}

	vendors := vendorSet{}
	netCache := map[string][2]string{}
	for _, id := range order {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if report.Reads >= lensMaxReads {
			w.truncate("database read limit")
			break
		}

		cur := owned[id]
		steps, err := w.steps(cur)
		if err != nil {
			return report, err
		}
		for _, s := range steps {
			if _, mine := owned[s.other.ID]; mine {
				continue
			}
			if err := w.vendorsFrom(cur, s, owned, ownDomains, netCache, vendors); err != nil {
				return report, err
			}
		}
	}
	for _, use := range vendors {
		if _, mine := owned[use.VendorID]; mine && use.VendorID != "" {
			continue
		}

		report.Vendors = append(report.Vendors, *use)
	}

	rank := map[string]int{}
	for i, k := range vendorKindOrder {
		rank[k] = i
	}

	sort.Slice(report.Vendors, func(i, j int) bool {
		a, b := report.Vendors[i], report.Vendors[j]
		if a.Kind != b.Kind {
			return rank[a.Kind] < rank[b.Kind]
		}
		if a.Assets != b.Assets {
			return a.Assets > b.Assets
		}

		return a.Vendor < b.Vendor
	})
	return report, nil
}

// vendorsFrom records the vendors that one step out of a controlled asset
// names.
func (w *lensWalker) vendorsFrom(cur Asset, s step, owned map[string]Asset, ownDomains map[string]bool, netCache map[string][2]string, vendors vendorSet) error {
	via := cur.Type + " " + s.edge.Label
	switch {
	case s.attr == attrThirdParty && s.forward:
		kind, ok := vendorKinds[s.edge.Label]
		if !ok {
			return nil
		}

		name, id, err := w.party(s.other)
		if err != nil || name == "" || (s.other.Type == "FQDN" && ownDomains[name]) {
			return err
		}

		vendors.add(name, id, kind, via, cur)
	case s.attr == "infrastructure" && s.forward && s.other.Type == "IPAddress":
		name, id, err := w.network(s.other, owned, netCache)
		if err != nil {
			return err
		}

		vendors.add(name, id, "Hosting and network providers", via+" IPAddress", cur)
	case s.attr == "infrastructure" && s.forward && cur.Type == "FQDN" && s.other.Type == "FQDN":
		domain := registeredDomain(fqdnName(s.other))
		if !ownDomains[domain] {
			vendors.add(domain, "", "DNS record targets (CNAME, NS, MX)", via, cur)
		}
	case s.attr == "infrastructure" && s.forward && s.other.Type == "Service":
		steps, err := w.steps(s.other)
		if err != nil {
			return err
		}
		for _, svc := range steps {
			kind, ok := vendorKinds[svc.edge.Label]
			if !ok || svc.attr != attrThirdParty || !svc.forward {
				continue
			}

			name, id, err := w.party(svc.other)
			if err != nil {
				return err
			}

			vendors.add(name, id, kind, via+" Service "+svc.edge.Label, cur)
		}
	case s.attr == "shared" && !s.forward && s.other.Type == "TLSCertificate":
		// A certificate that lists a controlled name was issued for it, so
		// its issuing authority is a vendor even if the certificate is shared.
		steps, err := w.steps(s.other)
		if err != nil {
			return err
		}
		for _, c := range steps {
			if c.forward && c.edge.Label == "issuer_contact" {
				name, id, err := w.party(c.other)
				if err != nil {
					return err
				}

				vendors.add(name, id, "Certificate authorities", "TLSCertificate issuer_contact", cur)
			}
		}
	}

	return nil
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
		"handle"); v != "" {
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

// vendorLanguage marks a question as being about outside parties.
var vendorLanguage = regexp.MustCompile(`(?i)\b(?:third[- ]part(?:y|ies)|vendors?|suppliers?|service providers?)\b`)

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

// promoteThirdPartyGoal turns a model goal for a vendor question about an
// Organization or FQDN into the third-party lens.
func promoteThirdPartyGoal(q *Query) bool {
	if !vendorLanguage.MatchString(q.Question) || len(q.Hops) != 0 ||
		(q.Subject.Type != "Organization" && q.Subject.Type != "FQDN") {
		return false
	}

	*q = thirdPartyQuery(q.Question, q.Subject, q.Source)
	return true
}
