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

// fingerprintSignals finds the services that share a stored fingerprint
// (JARM) with a service on a controlled name; the candidates are the names
// and addresses serving them.
func (g *gapSearch) fingerprintSignals(name Asset) error {
	def, ok := firstSignal(matchFingerprint)
	if !ok {
		return nil
	}

	steps, err := g.w.steps(name)
	if err != nil {
		return err
	}
	for _, s := range steps {
		if !s.forward || s.edge.Label != "port" || s.other.Type != "Service" || !g.read() {
			continue
		}

		evidence, err := g.w.graph.Evidence(g.w.ctx, s.other.ID, 100)
		if err != nil {
			return err
		}
		for _, value := range propertyValues(evidence, def.Params.Property) {
			if !g.read() {
				return nil
			}

			others, more, err := g.values.FindByTagValue(g.w.ctx, "Service", def.Params.Property, value, false,
				gapMaxShared+1)
			if err != nil {
				return err
			}
			if more || len(others) > gapMaxShared {
				continue
			}
			for _, o := range others {
				if o.ID == s.other.ID {
					continue
				}

				g.w.assets[o.ID] = o
				hosts, err := g.w.steps(o)
				if err != nil {
					return err
				}
				for _, h := range hosts {
					if h.forward || h.edge.Label != "port" || (h.other.Type != "FQDN" && h.other.Type != "IPAddress") {
						continue
					}

					witness := append(g.pathTo(name.ID), witnessOf(s.edge, name, s.other),
						matched(s.other, o, "same_"+strings.ToLower(def.Params.Property), value),
						witnessOf(h.edge, o, h.other))
					g.add(h.other, def.ID, "Service "+def.Params.Property+" Service", witness)
				}
			}
		}
	}

	return nil
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
