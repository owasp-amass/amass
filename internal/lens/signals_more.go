// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"encoding/json"
	"net/url"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// firstSignal returns the first catalog signal a matcher produces.
func firstSignal(matcher string) (OwnershipSignal, bool) {
	defs := signalsByMatcher(matcher)
	if len(defs) == 0 {
		return OwnershipSignal{}, false
	}

	return defs[0], true
}

// reverseDNS reports whether s, seen from a controlled name, is a reverse
// DNS record naming it.
func (g *gapSearch) reverseDNS(s step) bool {
	def, ok := firstSignal(matchReverseDNS)
	return ok && s.other.Type == "IPAddress" && slices.Contains(def.Params.Labels, s.edge.Label)
}

// reverseDNSSignals records an address whose reverse DNS names a
// controlled host, and the names that resolve to that address.
func (g *gapSearch) reverseDNSSignals(cur graph.Asset, s step, hop graph.WitnessEdge) error {
	def, _ := firstSignal(matchReverseDNS)
	addr := s.other
	witness := append(g.pathTo(cur.ID), hop)
	g.add(addr, def.ID, addr.Type+" "+s.edge.Label+" "+cur.Type, witness)

	steps, err := g.w.steps(addr)
	if err != nil {
		return err
	}

	var names []step
	for _, t := range steps {
		if !t.forward && t.other.Type == "FQDN" && t.edge.Label == "dns_record" {
			names = append(names, t)
		}
	}
	if len(names) > GapMaxShared {
		return nil
	}
	for _, t := range names {
		w := append(append([]graph.WitnessEdge(nil), witness...), WitnessOf(t.edge, addr, t.other))
		g.add(t.other, def.ID, "FQDN dns_record IPAddress "+s.edge.Label+" "+cur.Type, w)
	}

	return nil
}

// serviceHeaders returns a service's stored response headers, keyed by
// lowercase name.
func serviceHeaders(svc graph.Asset) map[string][]string {
	data, err := json.Marshal(ContentValue(svc, "attributes"))
	if err != nil {
		return nil
	}

	var raw map[string][]string
	if json.Unmarshal(data, &raw) != nil {
		return nil
	}

	out := make(map[string][]string, len(raw))
	for k, v := range raw {
		out[strings.ToLower(k)] = append(out[strings.ToLower(k)], v...)
	}

	return out
}

// ContentValue returns the raw value of one field of an asset's content.
func ContentValue(a graph.Asset, key string) any {
	data, err := json.Marshal(a.Content)
	if err != nil {
		return nil
	}

	var m map[string]any
	if json.Unmarshal(data, &m) != nil {
		return nil
	}

	return m[key]
}

// redirectHost returns the host a redirect header value points to: an
// absolute URL in Location or Content-Location, or the url= part of a
// Refresh value. Relative redirects stay on the same host and return "".
func redirectHost(header, value string) string {
	value = strings.TrimSpace(value)
	if header == "refresh" {
		i := strings.Index(strings.ToLower(value), "url=")
		if i < 0 {
			return ""
		}

		value = strings.Trim(strings.TrimSpace(value[i+len("url="):]), `'"`)
	}

	u, err := url.Parse(value)
	if err != nil {
		return ""
	}

	return u.Hostname()
}

// redirectSignals finds services that redirect into apex's namespace; the
// candidates are the names and addresses serving them.
func (g *gapSearch) redirectSignals(apex graph.Asset) error {
	def, ok := firstSignal(matchHTTPRedirect)
	name := strings.ToLower(graph.AssetLabel(apex))
	if !ok || name == "" || !g.read() {
		return nil
	}

	services, _, err := g.values.FindByAttribute(g.w.ctx, "Service", "attributes", name, true, gapMaxReferencing)
	if err != nil {
		return err
	}
	for _, svc := range services {
		headers := serviceHeaders(svc)
		var found string
		for _, h := range def.Params.Headers {
			h = strings.ToLower(h)
			for _, v := range headers[h] {
				if HostWithin(redirectHost(h, v), name) {
					found = h + ": " + v
					break
				}
			}
			if found != "" {
				break
			}
		}
		if found == "" {
			continue
		}

		g.w.assets[svc.ID] = svc
		steps, err := g.w.steps(svc)
		if err != nil {
			return err
		}
		for _, t := range steps {
			if t.forward || t.edge.Label != "port" || (t.other.Type != "FQDN" && t.other.Type != "IPAddress") {
				continue
			}

			witness := append(g.pathTo(apex.ID), matched(svc, apex, "redirects_to", found),
				WitnessOf(t.edge, svc, t.other))
			g.add(t.other, def.ID, "Service "+strings.SplitN(found, ":", 2)[0]+" FQDN", witness)
		}
	}

	return nil
}

// nameserverSignals finds the domain registrations that list every name
// server of a controlled registration, when those servers belong to a
// provider (the organization's own servers are the self-hosted DNS signal).
func (g *gapSearch) nameserverSignals(dr graph.Asset) error {
	def, ok := firstSignal(matchNameserverSet)
	if !ok {
		return nil
	}

	steps, err := g.w.steps(dr)
	if err != nil {
		return err
	}

	var servers []step
	for _, s := range steps {
		if s.forward && s.edge.Label == "name_server" {
			if _, mine := g.owned[s.other.ID]; mine {
				return nil
			}

			servers = append(servers, s)
		}
	}
	if len(servers) < def.Params.MinServers {
		return nil
	}

	var shared map[string]graph.Asset
	for _, ns := range servers {
		nsSteps, err := g.w.steps(ns.other)
		if err != nil {
			return err
		}

		listing := map[string]graph.Asset{}
		for _, t := range nsSteps {
			if !t.forward && t.edge.Label == "name_server" && t.other.ID != dr.ID {
				listing[t.other.ID] = t.other
			}
		}
		if shared == nil {
			shared = listing
			continue
		}
		for id := range shared {
			if _, ok := listing[id]; !ok {
				delete(shared, id)
			}
		}
	}
	if len(shared) == 0 || len(shared) > GapMaxShared {
		return nil
	}

	names := make([]string, 0, len(servers))
	for _, ns := range servers {
		names = append(names, graph.AssetLabel(ns.other))
	}

	sort.Strings(names)
	for _, d := range shared {
		witness := append(g.pathTo(dr.ID), matched(dr, d, "same_name_servers", strings.Join(names, ", ")))
		g.add(d, def.ID, "DomainRecord name_server set", witness)
	}

	return nil
}

// fingerprintSignals finds the assets that share a stored fingerprint (a
// JARM hash, page title, analytics identifier, content or favicon hash) with
// a service on a controlled name or with a controlled URL. Each catalog
// signal of the service_fingerprint matcher names its property and the
// asset types that carry it. A service's candidates are the names and
// addresses serving it; a URL is its own candidate.
// registrationContactLabels are the registration relations whose contact the
// registrant email-domain signal pivots from, across domain records
// (registrant_contact, …) and IP network and autonomous-system records
// (registrant). Abuse contacts are left out: they are usually the provider's
// abuse desk, not the owner's.
var registrationContactLabels = map[string]bool{
	"registrant_contact": true, "admin_contact": true, "technical_contact": true, "billing_contact": true,
	"registrant": true,
}

// emailDomainSignals finds other registration contacts whose email address is
// at the same custom domain as a contact of this controlled registration (a
// domain, IP network or autonomous-system record). Two registrations whose
// contacts use one organization's mail domain (admin@acme.com and
// security@acme.com) are almost always controlled by the same party, a link a
// shared exact email value misses.
func (g *gapSearch) emailDomainSignals(rec graph.Asset) error {
	def, ok := firstSignal(matchEmailDomain)
	if !ok || g.values == nil {
		return nil
	}

	free := make(map[string]bool, len(def.Params.FreeMail))
	for _, d := range def.Params.FreeMail {
		free[strings.ToLower(d)] = true
	}

	steps, err := g.w.steps(rec)
	if err != nil {
		return err
	}

	// The email domains of this registration's own contacts, each with the
	// controlled contact it came from, for the witness.
	owners := map[string]graph.Asset{}
	for _, s := range steps {
		if !s.forward || !registrationContactLabels[s.edge.Label] || s.other.Type != "ContactRecord" {
			continue
		}
		domains, _ := g.w.contactEmailDomains(s.other)
		for _, dom := range domains {
			if dom != "" && !free[dom] {
				owners[dom] = s.other
			}
		}
	}

	for dom, ctl := range owners {
		if !g.read() {
			return nil
		}

		others, more, err := g.values.FindByAttribute(g.w.ctx, "Identifier", "id", dom, true, GapMaxShared+1)
		if err != nil {
			return err
		}
		// A mail domain carried by many registrants is a provider or a free
		// service, not one owner's.
		if more || len(others) > GapMaxShared {
			continue
		}

		for _, id := range others {
			if !strings.EqualFold(graph.ContentString(id, "id_type"), "email") {
				continue
			}
			if _, dom2, ok := strings.Cut(strings.ToLower(graph.ContentString(id, "id")), "@"); !ok ||
				graph.RegisteredDomain(dom2) != dom {
				continue
			}

			g.w.assets[id.ID] = id
			idSteps, err := g.w.steps(id)
			if err != nil {
				return err
			}
			for _, t := range idSteps {
				if t.forward || t.edge.Label != "id" || t.other.Type != "ContactRecord" {
					continue
				}
				if _, mine := g.owned[t.other.ID]; mine || t.other.ID == ctl.ID {
					continue
				}

				witness := append(g.pathTo(rec.ID), matched(ctl, t.other, "same_email_domain", "@"+dom))
				g.add(t.other, def.ID, "ContactRecord email domain ContactRecord", witness)
			}
		}
	}

	return nil
}

// dkimSignals finds domains that publish the same DKIM public key as a
// controlled apex. A DKIM key in DNS pairs with a private key held by whoever
// signs the domain's mail, so the same public key on two domains means their
// mail is signed by the same private key, hence the same operator.
func (g *gapSearch) dkimSignals(apex graph.Asset) error {
	def, ok := firstSignal(matchDKIMKey)
	if !ok || g.values == nil {
		return nil
	}

	apexName := graph.FQDNName(apex)
	steps, err := g.w.steps(apex)
	if err != nil {
		return err
	}

	for _, s := range steps {
		// The DKIM keys live at <selector>._domainkey.<apex> names below the
		// apex, each linked to it as a node.
		if !s.forward || s.edge.Label != "node" || s.other.Type != "FQDN" ||
			!strings.HasSuffix(graph.FQDNName(s.other), "._domainkey."+apexName) {
			continue
		}
		if !g.read() {
			return nil
		}

		txts, err := g.txtRecords(s.other)
		if err != nil {
			return err
		}
		for _, txt := range txts {
			key := dkimPublicKey(txt)
			if len(key) < 40 {
				// Too short to be a real public key, or a revoked empty key.
				continue
			}

			others, more, err := g.values.FindByTagValue(g.w.ctx, "FQDN", graph.DNSRecordProperty, key, true,
				GapMaxShared+1)
			if err != nil {
				return err
			}
			// A key published by many domains is a provider's shared or
			// CNAME-delegated key, not one owner's.
			if more || len(others) > GapMaxShared {
				continue
			}

			for _, o := range others {
				if o.ID == s.other.ID {
					continue
				}
				// The candidate is the other key's registered domain, not the
				// _domainkey name that carries it.
				cand, ok := g.apexOfDKIM(o)
				if !ok {
					continue
				}

				witness := append(g.pathTo(apex.ID), matched(s.other, o, "same_dkim_key", "p="+key[:12]+"…"))
				g.add(cand, def.ID, "FQDN DKIM key FQDN", witness)
			}
		}
	}

	return nil
}

// apexOfDKIM resolves a <selector>._domainkey.<apex> name to its registered
// domain's apex asset, found as the node it hangs below.
func (g *gapSearch) apexOfDKIM(child graph.Asset) (graph.Asset, bool) {
	want := graph.RegisteredDomain(graph.FQDNName(child))
	if want == "" {
		return graph.Asset{}, false
	}

	steps, err := g.w.steps(child)
	if err != nil {
		return graph.Asset{}, false
	}
	for _, s := range steps {
		if !s.forward && s.edge.Label == "node" && s.other.Type == "FQDN" && graph.FQDNName(s.other) == want {
			return s.other, true
		}
	}
	return graph.Asset{}, false
}

// dkimPublicKey returns the base64 public key of a DKIM TXT record (the p=
// tag), or empty when the record is not DKIM or the key is revoked.
func dkimPublicKey(txt string) string {
	if !hasPrefixFold(strings.TrimSpace(txt), "v=DKIM1") {
		return ""
	}
	for _, part := range strings.Split(txt, ";") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "p="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// securityTxtLinkLabels are the Service relations whose target URL a
// security.txt reference signal checks for the organization's namespace.
var securityTxtLinkLabels = map[string]bool{
	"security_canonical": true, "security_policy": true, "security_encryption": true,
	"security_acknowledgments": true, "security_hiring": true,
}

// securityTxtRefSignals finds names the organization does not yet own whose
// security.txt names a contact at the organization's domain or a canonical or
// policy URL in its namespace. A security.txt is published by whoever runs the
// site, so pointing it at the organization is operator evidence.
func (g *gapSearch) securityTxtRefSignals(apex graph.Asset) error {
	def, ok := firstSignal(matchSecurityTxtRef)
	if !ok || g.values == nil {
		return nil
	}
	name := strings.ToLower(graph.AssetLabel(apex))
	if name == "" {
		return nil
	}

	// A canonical, policy or other link whose host is in the org namespace.
	if g.read() {
		urls, more, err := g.values.FindByAttribute(g.w.ctx, "URL", "url", name, true, GapMaxShared+1)
		if err != nil {
			return err
		}
		if !more && len(urls) <= GapMaxShared {
			for _, u := range urls {
				if !HostWithin(graph.ContentString(u, "host"), name) {
					continue
				}
				if svc, ok := g.reverseVia(u, securityTxtLinkLabels); ok {
					g.addSecurityTxtCandidate(apex, svc, "canonical "+graph.AssetLabel(u), def)
				}
			}
		}
	}

	// A security contact mailbox at the org domain, via the contact record.
	if g.read() {
		ids, more, err := g.values.FindByAttribute(g.w.ctx, "Identifier", "id", name, true, GapMaxShared+1)
		if err != nil {
			return err
		}
		if !more && len(ids) <= GapMaxShared {
			for _, id := range ids {
				if !strings.EqualFold(graph.ContentString(id, "id_type"), "email") {
					continue
				}
				if _, host, ok := strings.Cut(strings.ToLower(graph.ContentString(id, "id")), "@"); !ok ||
					!HostWithin(host, name) {
					continue
				}
				cr, ok := g.reverseVia(id, map[string]bool{"id": true})
				if !ok {
					continue
				}
				if svc, ok := g.reverseVia(cr, map[string]bool{"security_contact": true}); ok {
					g.addSecurityTxtCandidate(apex, svc, "contact "+graph.ContentString(id, "id"), def)
				}
			}
		}
	}
	return nil
}

// reverseVia returns the asset that points to target through one of labels.
func (g *gapSearch) reverseVia(target graph.Asset, labels map[string]bool) (graph.Asset, bool) {
	steps, err := g.w.steps(target)
	if err != nil {
		return graph.Asset{}, false
	}
	for _, s := range steps {
		if !s.forward && labels[s.edge.Label] {
			return s.other, true
		}
	}
	return graph.Asset{}, false
}

// addSecurityTxtCandidate adds the FQDN that a referencing service hangs off.
func (g *gapSearch) addSecurityTxtCandidate(apex, service graph.Asset, detail string, def OwnershipSignal) {
	host, ok := g.reverseVia(service, map[string]bool{"port": true})
	if !ok || host.Type != "FQDN" {
		return
	}
	witness := append(g.pathTo(apex.ID), matched(apex, host, "security_txt_reference", detail))
	g.add(host, def.ID, "FQDN security.txt FQDN", witness)
}

func (g *gapSearch) fingerprintSignals(owned graph.Asset) error {
	defs := signalsByMatcher(matchFingerprint)
	if len(defs) == 0 {
		return nil
	}

	var sources []graph.WitnessEdge
	var assets []graph.Asset
	switch owned.Type {
	case "URL":
		sources, assets = []graph.WitnessEdge{{}}, []graph.Asset{owned}
	case "FQDN", "IPAddress":
		steps, err := g.w.steps(owned)
		if err != nil {
			return err
		}
		for _, s := range steps {
			if s.forward && s.edge.Label == "port" && s.other.Type == "Service" {
				sources = append(sources, WitnessOf(s.edge, owned, s.other))
				assets = append(assets, s.other)
			}
		}
	}
	for i, src := range assets {
		if !g.read() {
			return nil
		}

		steps, err := g.w.steps(src)
		if err != nil {
			return err
		}
		for _, s := range steps {
			if !s.forward || s.edge.Label != "fingerprint" || s.other.Type != "Identifier" {
				continue
			}

			idType := graph.ContentString(s.other, "id_type")
			value := graph.ContentString(s.other, "id")
			for _, def := range defs {
				if !strings.EqualFold(def.Params.Property, idType) ||
					!slices.Contains(fingerprintTypes(def), src.Type) || !usefulFingerprint(def, value) {
					continue
				}

				lead := g.pathTo(owned.ID)
				if sources[i].Label != "" {
					lead = append(lead, sources[i])
				}
				lead = append(lead, WitnessOf(s.edge, src, s.other))
				if err := g.fingerprintMatches(def, src, s.other, lead); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// fingerprintMatches records the candidates behind the other assets that share
// the fingerprint Identifier ident with src, unless more than GapMaxShared do.
// The shared Identifier is the pivot: its incoming "fingerprint" edges are the
// assets carrying the same value, read bounded so a value on many hosts (a
// common favicon or title) is skipped rather than walked in full.
func (g *gapSearch) fingerprintMatches(def OwnershipSignal, src, ident graph.Asset, lead []graph.WitnessEdge) error {
	if !g.read() {
		return nil
	}

	edges, more, err := graph.ReadEdges(g.w.ctx, g.w.graph, ident.ID, "in", "fingerprint", GapMaxShared+1, g.read)
	if err != nil {
		return err
	}
	if more || len(edges) > GapMaxShared {
		return nil
	}

	for _, edge := range edges {
		if edge.FromID == src.ID || edge.FromID == ident.ID {
			continue
		}

		o, err := g.w.asset(edge.FromID)
		if err != nil {
			return err
		}
		if !slices.Contains(fingerprintTypes(def), o.Type) {
			continue
		}

		g.w.assets[o.ID] = o
		match := WitnessOf(edge, ident, o)
		via := src.Type + " " + def.Params.Property + " " + o.Type
		if o.Type != "Service" {
			g.add(o, def.ID, via, append(append([]graph.WitnessEdge(nil), lead...), match))
			continue
		}

		hosts, err := g.w.steps(o)
		if err != nil {
			return err
		}
		for _, h := range hosts {
			if h.forward || h.edge.Label != "port" || (h.other.Type != "FQDN" && h.other.Type != "IPAddress") {
				continue
			}

			g.add(h.other, def.ID, via, append(append([]graph.WitnessEdge(nil), lead...), match,
				WitnessOf(h.edge, o, h.other)))
		}
	}

	return nil
}

// fingerprintTypes are the asset types a fingerprint signal reads.
func fingerprintTypes(def OwnershipSignal) []string {
	if len(def.Params.AssetTypes) > 0 {
		return def.Params.AssetTypes
	}

	return []string{"Service"}
}

// usefulFingerprint reports whether a stored value can tell owners apart:
// long enough, and not one of the signal's generic values (default pages,
// error pages, provider challenges).
func usefulFingerprint(def OwnershipSignal, value string) bool {
	v := strings.TrimSpace(value)
	if len(v) < def.Params.MinLength {
		return false
	}
	for _, ignore := range def.Params.IgnoreValues {
		if strings.EqualFold(v, strings.TrimSpace(ignore)) {
			return false
		}
	}

	return true
}

// propertyValues returns the values of an asset's stored simple properties
// named name.
func propertyValues(evidence []graph.Evidence, name string) []string {
	var out []string
	for _, e := range evidence {
		data, err := json.Marshal(e.Property)
		if err != nil {
			continue
		}

		var p struct {
			Name  string `json:"property_name"`
			Value string `json:"property_value"`
		}
		if json.Unmarshal(data, &p) == nil && strings.EqualFold(p.Name, name) && p.Value != "" &&
			!slices.Contains(out, p.Value) {
			out = append(out, p.Value)
		}
	}

	return out
}

// contextSignals adds the signals judged from a candidate other evidence
// already found: a distinctive word of the owner's name in the candidate's
// name, and a parked or for-sale page against it.
func (g *gapSearch) contextSignals(a graph.Asset, c *GapCandidate) error {
	if def, ok := firstSignal(matchNameToken); ok {
		label := strings.ToLower(c.Asset)
		for _, tok := range nameTokens(graph.AssetLabel(g.owner), def.Params) {
			if strings.Contains(label, tok) {
				g.add(a, def.ID, "name "+tok, []graph.WitnessEdge{matched(g.owner, a, "name_contains", tok)})
				break
			}
		}
	}

	def, ok := firstSignal(matchParkedPage)
	if !ok || a.Type != "FQDN" {
		return nil
	}

	steps, err := g.w.steps(a)
	if err != nil {
		return err
	}
	for _, s := range steps {
		if !s.forward || s.edge.Label != "port" || s.other.Type != "Service" {
			continue
		}

		page := strings.ToLower(graph.ContentString(s.other, "output"))
		for _, phrase := range def.Params.Phrases {
			if phrase = strings.ToLower(phrase); phrase != "" && strings.Contains(page, phrase) {
				g.add(a, def.ID, "Service page", []graph.WitnessEdge{WitnessOf(s.edge, a, s.other),
					matched(s.other, a, "page_says", phrase)})
				return nil
			}
		}
	}

	return nil
}

// nameTokens returns the distinctive words of an organization's name.
func nameTokens(name string, params SignalParams) []string {
	words := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})

	var out []string
	for _, w := range words {
		if len(w) >= params.MinLength && !slices.Contains(params.StopWords, w) && !slices.Contains(out, w) {
			out = append(out, w)
		}
	}

	return out
}
