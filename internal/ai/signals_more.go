// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"encoding/json"
	"net/url"
	"slices"
	"sort"
	"strings"
	"unicode"
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
func (g *gapSearch) reverseDNSSignals(cur Asset, s step, hop WitnessEdge) error {
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
	if len(names) > gapMaxShared {
		return nil
	}
	for _, t := range names {
		w := append(append([]WitnessEdge(nil), witness...), witnessOf(t.edge, addr, t.other))
		g.add(t.other, def.ID, "FQDN dns_record IPAddress "+s.edge.Label+" "+cur.Type, w)
	}

	return nil
}

// serviceHeaders returns a service's stored response headers, keyed by
// lowercase name.
func serviceHeaders(svc Asset) map[string][]string {
	data, err := json.Marshal(contentValue(svc, "attributes"))
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

// contentValue returns the raw value of one field of an asset's content.
func contentValue(a Asset, key string) any {
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
func (g *gapSearch) redirectSignals(apex Asset) error {
	def, ok := firstSignal(matchHTTPRedirect)
	name := strings.ToLower(assetLabel(apex))
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
				if hostWithin(redirectHost(h, v), name) {
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
				witnessOf(t.edge, svc, t.other))
			g.add(t.other, def.ID, "Service "+strings.SplitN(found, ":", 2)[0]+" FQDN", witness)
		}
	}

	return nil
}

// nameserverSignals finds the domain registrations that list every name
// server of a controlled registration, when those servers belong to a
// provider (the organization's own servers are the self-hosted DNS signal).
func (g *gapSearch) nameserverSignals(dr Asset) error {
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

	var shared map[string]Asset
	for _, ns := range servers {
		nsSteps, err := g.w.steps(ns.other)
		if err != nil {
			return err
		}

		listing := map[string]Asset{}
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
	if len(shared) == 0 || len(shared) > gapMaxShared {
		return nil
	}

	names := make([]string, 0, len(servers))
	for _, ns := range servers {
		names = append(names, assetLabel(ns.other))
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
func (g *gapSearch) fingerprintSignals(owned Asset) error {
	defs := signalsByMatcher(matchFingerprint)
	if len(defs) == 0 {
		return nil
	}

	var sources []WitnessEdge
	var assets []Asset
	switch owned.Type {
	case "URL":
		sources, assets = []WitnessEdge{{}}, []Asset{owned}
	case "FQDN", "IPAddress":
		steps, err := g.w.steps(owned)
		if err != nil {
			return err
		}
		for _, s := range steps {
			if s.forward && s.edge.Label == "port" && s.other.Type == "Service" {
				sources = append(sources, witnessOf(s.edge, owned, s.other))
				assets = append(assets, s.other)
			}
		}
	}
	for i, src := range assets {
		if !g.read() {
			return nil
		}

		evidence, err := g.w.graph.Evidence(g.w.ctx, src.ID, 100)
		if err != nil {
			return err
		}
		for _, def := range defs {
			if !slices.Contains(fingerprintTypes(def), src.Type) {
				continue
			}
			for _, value := range propertyValues(evidence, def.Params.Property) {
				if !usefulFingerprint(def, value) {
					continue
				}

				lead := g.pathTo(owned.ID)
				if sources[i].Label != "" {
					lead = append(lead, sources[i])
				}
				if err := g.fingerprintMatches(def, owned, src, value, lead); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// fingerprintMatches records the candidates behind the assets that carry
// value, unless more than gapMaxShared do.
func (g *gapSearch) fingerprintMatches(def OwnershipSignal, owned, src Asset, value string, lead []WitnessEdge) error {
	for _, t := range fingerprintTypes(def) {
		if !g.read() {
			return nil
		}

		others, more, err := g.values.FindByTagValue(g.w.ctx, t, def.Params.Property, value, false, gapMaxShared+1)
		if err != nil {
			return err
		}
		if more || len(others) > gapMaxShared {
			continue
		}
		for _, o := range others {
			if o.ID == src.ID || o.ID == owned.ID {
				continue
			}

			g.w.assets[o.ID] = o
			match := matched(src, o, "same_"+strings.ToLower(def.Params.Property), value)
			via := src.Type + " " + def.Params.Property + " " + o.Type
			if o.Type != "Service" {
				g.add(o, def.ID, via, append(append([]WitnessEdge(nil), lead...), match))
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

				g.add(h.other, def.ID, via, append(append([]WitnessEdge(nil), lead...), match,
					witnessOf(h.edge, o, h.other)))
			}
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
func propertyValues(evidence []Evidence, name string) []string {
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
func (g *gapSearch) contextSignals(a Asset, c *GapCandidate) error {
	if def, ok := firstSignal(matchNameToken); ok {
		label := strings.ToLower(c.Asset)
		for _, tok := range nameTokens(assetLabel(g.owner), def.Params) {
			if strings.Contains(label, tok) {
				g.add(a, def.ID, "name "+tok, []WitnessEdge{matched(g.owner, a, "name_contains", tok)})
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

		page := strings.ToLower(contentString(s.other, "output"))
		for _, phrase := range def.Params.Phrases {
			if phrase = strings.ToLower(phrase); phrase != "" && strings.Contains(page, phrase) {
				g.add(a, def.ID, "Service page", []WitnessEdge{witnessOf(s.edge, a, s.other),
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
