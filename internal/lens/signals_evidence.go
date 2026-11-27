// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"errors"
	"html"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// caaAccountSignals finds the domains whose CAA records bind certificate
// issuance to the same ACME account (accounturi, RFC 8657) as apex's.
func (g *gapSearch) caaAccountSignals(apex graph.Asset) error {
	def, ok := firstSignal(matchCAAAccount)
	if !ok || !g.read() {
		return nil
	}

	records, err := graph.CAAValues(g.w.ctx, g.w.graph, apex.ID)
	if err != nil {
		return err
	}

	seen := map[string]bool{}
	for _, rec := range records {
		uri := caaAccountURI(rec)
		if uri == "" || seen[uri] || !g.read() {
			continue
		}
		seen[uri] = true

		others, more, err := g.values.FindByTagValue(g.w.ctx, "FQDN", graph.DNSRecordProperty, "accounturi="+uri, true,
			g.searchBound(GapMaxShared, "FQDN"))
		if err != nil {
			return err
		}
		others = g.outsideAssets(others)
		if g.fixed("CAA account URI").over(uri, len(others), more) {
			continue
		}
		for _, o := range others {
			if o.ID == apex.ID {
				continue
			}
			if _, mine := g.owned[o.ID]; mine || !g.read() {
				continue
			}

			// the search matches a prefix of the URI, so the account is confirmed
			theirs, err := graph.CAAValues(g.w.ctx, g.w.graph, o.ID)
			if err != nil {
				return err
			}
			if !caaHasAccount(theirs, uri) {
				continue
			}

			witness := append(g.pathTo(apex.ID), matched(apex, o, "same_caa_accounturi", uri))
			g.add(o, def.ID, "FQDN CAA accounturi FQDN", witness)
		}
	}

	return nil
}

// caaAccountURI returns the accounturi parameter of an issue or issuewild CAA
// record rendered as `<flags> <tag> "<value>"`, or "".
func caaAccountURI(rec string) string {
	fields := strings.SplitN(strings.TrimSpace(rec), " ", 3)
	if len(fields) != 3 {
		return ""
	}
	if tag := strings.ToLower(fields[1]); tag != "issue" && tag != "issuewild" {
		return ""
	}

	value := strings.Trim(strings.TrimSpace(fields[2]), `"`)
	params := strings.Split(value, ";")
	for _, p := range params[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "accounturi") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// caaHasAccount reports whether one of the CAA records binds the account.
func caaHasAccount(records []string, uri string) bool {
	for _, rec := range records {
		if caaAccountURI(rec) == uri {
			return true
		}
	}
	return false
}

// securityTxtKeySignals finds the names whose security.txt gives the same
// Encryption key URL as a security.txt of apex. A key URL in apex's own
// namespace is the security.txt reference signal's.
func (g *gapSearch) securityTxtKeySignals(apex graph.Asset) error {
	def, ok := firstSignal(matchSecurityTxtKey)
	name := strings.ToLower(graph.AssetLabel(apex))
	if !ok || name == "" || !g.read() {
		return nil
	}

	var keys []graph.Asset
	for _, st := range readSecurityTxt(g.w.ctx, g.w.graph, apex) {
		for _, u := range st.urls {
			if u.field == "encryption" && !HostWithin(graph.ContentString(u.url, "host"), name) {
				keys = append(keys, u.url)
			}
		}
	}

	return g.securityTxtRefs(apex, keys, "URL", "url", def, func(u graph.Asset) string {
		return "encryption key " + graph.AssetLabel(u)
	})
}

// privateAddressSignals finds the names under other registered domains that
// resolve to at least min_shared of the private or reserved addresses the
// subject's names resolve to: names from the same internal DNS.
func (g *gapSearch) privateAddressSignals(order []string) error {
	def, ok := firstSignal(matchPrivateAddress)
	if !ok {
		return nil
	}

	var ignore []netip.Prefix
	for _, r := range def.Params.IgnoreRanges {
		if p, err := netip.ParsePrefix(r); err == nil {
			ignore = append(ignore, p.Masked())
		}
	}

	type share struct {
		witness []graph.WitnessEdge
		via     string
	}
	// by the other name's registered domain: the addresses shared, and each
	// name's witnesses
	addrs := map[string]map[string]bool{}
	names := map[string]map[string][]share{}
	others := map[string]graph.Asset{}

	for _, id := range order {
		owned := g.owned[id]
		if owned.Type != "FQDN" {
			continue
		}
		if g.w.outOfReads() {
			break
		}

		steps, err := g.w.steps(owned)
		if err != nil {
			return err
		}
		for _, s := range steps {
			if !s.forward || s.edge.Label != "dns_record" || s.other.Type != "IPAddress" {
				continue
			}
			addr, err := netip.ParseAddr(graph.ContentString(s.other, "address"))
			if err != nil || !reservedAddress(addr) || commonPrivateAddress(addr, ignore) {
				continue
			}

			holders, err := g.w.steps(s.other)
			if err != nil {
				return err
			}
			var resolving []step
			for _, t := range holders {
				if !t.forward && t.edge.Label == "dns_record" && t.other.Type == "FQDN" {
					resolving = append(resolving, t)
				}
			}
			resolving = g.outsideSteps(resolving)
			if g.hub("dns_record", "in", GapMaxShared).over(graph.AssetLabel(s.other), len(resolving), false) {
				continue
			}

			hop := WitnessOf(s.edge, owned, s.other)
			for _, t := range resolving {
				other := t.other
				if _, mine := g.owned[other.ID]; mine || g.inOwnedNamespace(other) {
					continue
				}

				domain := graph.RegisteredDomain(graph.FQDNName(other))
				if domain == "" {
					continue
				}
				if addrs[domain] == nil {
					addrs[domain], names[domain] = map[string]bool{}, map[string][]share{}
				}
				addrs[domain][s.other.ID] = true
				others[other.ID] = other
				witness := append(append(g.pathTo(owned.ID), hop), WitnessOf(t.edge, s.other, other))
				names[domain][other.ID] = append(names[domain][other.ID],
					share{witness: witness, via: "FQDN dns_record IPAddress " + addr.String()})
			}
		}
	}

	domains := make([]string, 0, len(addrs))
	for d := range addrs {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	for _, d := range domains {
		if len(addrs[d]) < def.Params.MinShared {
			continue
		}
		for id, shares := range names[d] {
			for _, sh := range shares {
				g.add(others[id], def.ID, sh.via, sh.witness)
			}
		}
	}

	return nil
}

// commonPrivateAddress reports whether an address is too common to identify
// an internal network: in one of the ignored default ranges, or an IPv4
// address ending in .0, .1, .254 or .255 (network, gateway and broadcast
// addresses).
func commonPrivateAddress(addr netip.Addr, ignore []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, p := range ignore {
		if p.Contains(addr) {
			return true
		}
	}
	if addr.Is4() {
		switch addr.As4()[3] {
		case 0, 1, 254, 255:
			return true
		}
	}
	return false
}

// markCertificateSignals finds the names covered by BIMI mark certificates
// whose subject carries the subject organization's own LEI: the certificate
// authority verified them as the organization's.
func (g *gapSearch) markCertificateSignals() error {
	def, ok := firstSignal(matchMarkCertificate)
	if !ok {
		return nil
	}

	rules := loadCertificateRules()
	mr := rules.MarkCertificates
	steps, err := g.w.steps(g.owner)
	if err != nil {
		return err
	}
	for _, s := range steps {
		if !s.forward || s.edge.Label != mr.IdentifierLabel || s.other.Type != "Identifier" ||
			!strings.EqualFold(graph.ContentString(s.other, "id_type"), mr.LEIIDType) {
			continue
		}

		holders, err := g.w.steps(s.other)
		if err != nil {
			return err
		}
		for _, h := range holders {
			if h.forward || h.edge.Label != mr.IdentifierLabel || h.other.Type != "ContactRecord" {
				continue
			}
			if err := g.markCertificateNames(def, rules, s, h); err != nil {
				return err
			}
		}
	}

	return nil
}

// markCertificateNames adds the names covered by the mark certificates whose
// subject is the contact record h reaches.
func (g *gapSearch) markCertificateNames(def OwnershipSignal, rules certificateRules, own, h step) error {
	cr, lei := h.other, own.other
	certs, err := g.w.steps(cr)
	if err != nil {
		return err
	}
	for _, c := range certs {
		if c.forward || c.edge.Label != rules.MarkCertificates.SubjectLabel || c.other.Type != "TLSCertificate" ||
			!isMarkCertificate(c.other, rules) {
			continue
		}

		cert := c.other
		named, err := g.w.steps(cert)
		if err != nil {
			return err
		}
		for _, n := range named {
			if !n.forward || n.other.Type != "FQDN" || (n.edge.Label != "common_name" && n.edge.Label != "san_dns_name") {
				continue
			}

			witness := []graph.WitnessEdge{WitnessOf(own.edge, g.owner, lei), WitnessOf(h.edge, lei, cr),
				WitnessOf(c.edge, cert, cr), WitnessOf(n.edge, cert, n.other)}
			g.add(n.other, def.ID, "TLSCertificate mark subject LEI Organization", witness)
		}
	}

	return nil
}

// pageOrganizationSignals finds the services whose page carries a copyright
// notice for the subject organization or describes it in schema.org
// Organization markup; the candidates are the names and addresses serving
// them.
func (g *gapSearch) pageOrganizationSignals() error {
	def, ok := firstSignal(matchPageOrganization)
	if !ok || g.values == nil {
		return nil
	}

	seen := map[string]bool{}
	for _, name := range []string{graph.ContentString(g.owner, "name"), graph.ContentString(g.owner, "legal_name")} {
		name = strings.TrimSpace(name)
		key := semantics.OrgNameKey(name)
		if len(name) < def.Params.MinLength || key == "" || seen[key] ||
			semantics.IsPlaceholderOrganization(name) || !g.read() {
			continue
		}
		seen[key] = true

		// every page containing the name, since a search by part of the
		// text matches pages that do not name the organization
		matches, _, err := g.values.FindByAttribute(g.w.ctx, "Service", "output", name, true, 0)
		if errors.Is(err, ErrValueSearchUnsupported) {
			return nil
		} else if err != nil {
			return err
		}
		type naming struct {
			svc graph.Asset
			how string
		}
		var services []naming
		for _, svc := range g.outsideAssets(matches) {
			if how := pageNamesOrganization(graph.ContentString(svc, "output"), name); how != "" {
				services = append(services, naming{svc: svc, how: how})
			}
		}
		if g.fixed("name in service output").over(name, len(services), false) {
			continue
		}
		for _, n := range services {
			svc, how := n.svc, n.how

			hosts, err := g.w.steps(svc)
			if err != nil {
				return err
			}
			for _, h := range hosts {
				if h.forward || h.edge.Label != "port" || (h.other.Type != "FQDN" && h.other.Type != "IPAddress") {
					continue
				}

				witness := []graph.WitnessEdge{matched(svc, g.owner, "page_names_organization", how),
					WitnessOf(h.edge, h.other, svc)}
				g.add(h.other, def.ID, "Service page names Organization", witness)
			}
		}
	}

	return nil
}

var (
	pageTags  = regexp.MustCompile(`(?s)<[^>]*>`)
	pageSpace = regexp.MustCompile(`\s+`)
	// schemaOrganization finds a schema.org Organization type in JSON-LD
	// markup.
	schemaOrganization = regexp.MustCompile(`(?i)"@type"\s*:\s*"(?:Organization|Corporation|` +
		`CollegeOrUniversity|EducationalOrganization|GovernmentOrganization|NGO|NewsMediaOrganization|` +
		`MedicalOrganization|LocalBusiness)"`)
)

// schemaWindow is how far from an Organization type its name may be in the
// markup.
const schemaWindow = 400

// pageNamesOrganization returns how a page names the organization: a
// copyright notice for it, or the name of a schema.org Organization in its
// markup, or "" when it does neither.
func pageNamesOrganization(page, name string) string {
	if page == "" || name == "" {
		return ""
	}

	text := html.UnescapeString(pageTags.ReplaceAllString(page, " "))
	text = pageSpace.ReplaceAllString(text, " ")
	notice := regexp.MustCompile(`(?i)(?:©|\(c\)|copyright)\s*(?:\d{4}(?:\s*[-–]\s*\d{4})?)?\s*,?\s*(?:by\s+)?(?:the\s+)?` +
		regexp.QuoteMeta(name) + `\b`)
	if m := notice.FindString(text); m != "" {
		return strings.TrimSpace(m)
	}

	quoted := regexp.MustCompile(`(?i)"name"\s*:\s*"` + regexp.QuoteMeta(name) + `"`)
	for _, loc := range schemaOrganization.FindAllStringIndex(page, -1) {
		lo, hi := max(0, loc[0]-schemaWindow), min(len(page), loc[1]+schemaWindow)
		if quoted.MatchString(page[lo:hi]) {
			return "schema.org Organization " + name
		}
	}
	return ""
}

// pageHost finds the hosts of the URLs a page loads from or links to.
var pageHost = regexp.MustCompile(`(?i)(?:https?:)?//([a-z0-9][a-z0-9.-]*\.[a-z]{2,})`)

// bucketReferenceSignals finds the object-storage bucket hosts that the
// pages of a controlled name or address load from or link to.
func (g *gapSearch) bucketReferenceSignals(owned graph.Asset) error {
	def, ok := firstSignal(matchPageBucket)
	if !ok || g.values == nil {
		return nil
	}

	steps, err := g.w.steps(owned)
	if err != nil {
		return err
	}
	for _, s := range steps {
		if !s.forward || s.edge.Label != "port" || s.other.Type != "Service" {
			continue
		}

		svc := s.other
		for _, host := range bucketHosts(graph.ContentString(svc, "output")) {
			if !g.read() {
				return nil
			}

			// a repository without attribute searches gives this signal
			// nothing, and the other value signals still run
			found, _, err := g.values.FindByAttribute(g.w.ctx, "FQDN", "name", host, false, 1)
			if errors.Is(err, ErrValueSearchUnsupported) {
				return nil
			} else if err != nil {
				return err
			}
			for _, f := range found {
				witness := append(g.pathTo(owned.ID), WitnessOf(s.edge, owned, svc),
					matched(svc, f, "page_references", host))
				g.add(f, def.ID, "Service page references FQDN", witness)
			}
		}
	}

	return nil
}

// bucketHosts returns the distinct object-storage bucket hosts a page names,
// every one.
func bucketHosts(page string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range pageHost.FindAllStringSubmatch(page, -1) {
		host := strings.ToLower(strings.TrimSuffix(m[1], "."))
		if seen[host] {
			continue
		}
		seen[host] = true

		if _, bucket, ok := semantics.MatchBucketHost(host); ok && bucket != "" {
			out = append(out, host)
		}
	}
	return out
}

// organizationSignals runs the signals found from the subject organization
// itself: mark certificates for its LEI and pages that name it.
func (g *gapSearch) organizationSignals() error {
	if err := g.markCertificateSignals(); err != nil {
		return err
	}
	return g.pageOrganizationSignals()
}
