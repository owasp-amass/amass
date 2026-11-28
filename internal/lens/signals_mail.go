// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

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

		// every identifier containing the domain, since the search matches it
		// as part of the text; the other contact records holding a mailbox at
		// the domain are counted
		ids, _, err := g.values.FindByAttribute(g.w.ctx, "Identifier", "id", dom, true, 0)
		if err != nil {
			return err
		}
		var contacts []graph.Asset
		seen := map[string]bool{ctl.ID: true}
		for _, id := range ids {
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
				if t.forward || t.edge.Label != "id" || t.other.Type != "ContactRecord" || seen[t.other.ID] {
					continue
				}
				seen[t.other.ID] = true
				contacts = append(contacts, t.other)
			}
		}
		contacts = g.outsideAssets(contacts)
		// A mail domain carried by many other registrants is a provider or a
		// free service, not one owner's.
		if g.fixed(def, "registrant mail domain").over(dom, len(contacts), false) {
			continue
		}
		for _, cr := range contacts {
			witness := append(g.pathTo(rec.ID), matched(ctl, cr, "same_email_domain", "@"+dom))
			g.add(cr, def.ID, "ContactRecord email domain ContactRecord", witness)
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

			hub := g.fixed(def, "DKIM public key")
			others, more, err := g.values.FindByTagValue(g.w.ctx, "FQDN", graph.DNSRecordProperty, key, true,
				g.searchBound(hub.rule.Limit, "FQDN"))
			if err != nil {
				return err
			}
			others = g.outsideAssets(others)
			// A key published by many domains is a provider's shared or
			// CNAME-delegated key, not one owner's.
			if hub.over(graph.AssetLabel(s.other)+" DKIM key", len(others), more) {
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

	// A canonical, policy or other link whose host is in the org namespace,
	// and a security contact mailbox at the org domain. Every one counts, the
	// organization's own included: the candidate is the site whose
	// security.txt names it, and how many files name it is what is limited.
	if g.read() {
		urls, _, err := g.values.FindByAttribute(g.w.ctx, "URL", "url", name, true, 0)
		if err != nil {
			return err
		}
		var refs []graph.Asset
		for _, u := range urls {
			if HostWithin(graph.ContentString(u, "host"), name) {
				refs = append(refs, u)
			}
		}
		if err := g.securityTxtRefs(apex, refs, "URL", "url", def, func(u graph.Asset) string {
			return "link " + graph.AssetLabel(u)
		}); err != nil {
			return err
		}
	}
	if g.read() {
		ids, _, err := g.values.FindByAttribute(g.w.ctx, "Identifier", "id", name, true, 0)
		if err != nil {
			return err
		}
		var refs []graph.Asset
		for _, id := range ids {
			if !strings.EqualFold(graph.ContentString(id, "id_type"), "email") {
				continue
			}
			if _, host, ok := strings.Cut(strings.ToLower(graph.ContentString(id, "id")), "@"); ok &&
				HostWithin(host, name) {
				refs = append(refs, id)
			}
		}
		if err := g.securityTxtRefs(apex, refs, "Identifier", "id", def, func(id graph.Asset) string {
			return "contact " + graph.ContentString(id, "id")
		}); err != nil {
			return err
		}
	}
	return nil
}

// securityTxtRefs adds the names whose security.txt names one of refs (URLs
// or email Identifiers), finding in one step read the contact records that
// name them (ContactRecord --label--> ref); detail describes a ref in the
// witness.
func (g *gapSearch) securityTxtRefs(apex graph.Asset, refs []graph.Asset, refType, label string,
	def OwnershipSignal, detail func(graph.Asset) string) error {
	if len(refs) == 0 || !g.read() {
		return nil
	}

	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		g.w.assets[r.ID] = r
		ids = append(ids, r.ID)
	}
	edges, err := graph.StepsFrom(g.w.ctx, g.w.graph, ids, []graph.Step{{FromType: "ContactRecord", Label: label,
		RelationType: "SimpleRelation", ToType: refType}})
	if err != nil {
		return err
	}
	if err := g.w.readAssets(edges); err != nil {
		return err
	}

	contacts := map[string][]graph.Asset{}
	for _, e := range edges {
		if from := g.w.assets[e.FromID]; from.Type == "ContactRecord" {
			contacts[e.ToID] = append(contacts[e.ToID], from)
		}
	}
	for _, r := range refs {
		if len(contacts[r.ID]) > 0 {
			g.addSecurityTxtCandidates(apex, contacts[r.ID], detail(r), def)
		}
	}
	return nil
}

// addSecurityTxtCandidates adds the names whose security.txt names a value
// through one of the contact records holding it: URL(security.txt)
// --contact--> ContactRecord, URL --domain--> the name.
func (g *gapSearch) addSecurityTxtCandidates(apex graph.Asset, contacts []graph.Asset, detail string,
	def OwnershipSignal) {
	// A value published in more files outside the footprint than the limit
	// (a managed provider's contact, a copied template) says nothing about
	// any one of them.
	var hosts []graph.Asset
	for _, cr := range contacts {
		for _, file := range securityTxtFilesOf(g.w.ctx, g.w.graph, cr) {
			host, ok := fileHost(g.w.ctx, g.w.graph, file)
			if _, mine := g.owned[host.ID]; !ok || mine {
				continue
			}

			hosts = append(hosts, host)
			if g.fixed(def, "security.txt files").over(detail, len(hosts), false) {
				return
			}
		}
	}
	for _, host := range hosts {
		witness := append(g.pathTo(apex.ID), matched(apex, host, "security_txt_reference", detail))
		g.add(host, def.ID, "FQDN security.txt FQDN", witness)
	}
}
