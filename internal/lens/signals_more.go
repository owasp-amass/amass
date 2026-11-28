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
	names = g.outsideSteps(names)
	if g.hub(def, "dns_record", "in").over(graph.AssetLabel(addr), len(names), false) {
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

	services, _, err := g.values.FindByAttribute(g.w.ctx, "Service", "attributes", name, true, 0)
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

	// What sharing the set means depends on how its provider assigns name
	// servers: a provider whose customers share servers gives no evidence, and
	// one that gives each account or zone a set drawn from a large pool gives
	// strong evidence when the whole set matches.
	hosts := make([]string, 0, len(servers))
	for _, ns := range servers {
		hosts = append(hosts, graph.AssetLabel(ns.other))
	}
	via := "DomainRecord name_server set"
	if p, ok := nameServerSetProvider(hosts); ok {
		switch p.Assignment {
		case AssignmentShared:
			return nil
		case AssignmentUniqueSet:
			if strong, ok := firstSignal(matchProviderNameserverSet); ok && len(servers) >= strong.Params.MinServers {
				def, via = strong, "DomainRecord name_server set ("+p.Provider+")"
			}
		}
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
	for id := range shared {
		if _, mine := g.owned[id]; mine {
			delete(shared, id)
		}
	}
	if len(shared) == 0 ||
		g.hub(def, "name_server", "in").over("the name servers of "+graph.AssetLabel(dr), len(shared), false) {
		return nil
	}

	names := make([]string, 0, len(servers))
	for _, ns := range servers {
		names = append(names, graph.AssetLabel(ns.other))
	}

	sort.Strings(names)
	for _, d := range shared {
		witness := append(g.pathTo(dr.ID), matched(dr, d, "same_name_servers", strings.Join(names, ", ")))
		g.add(d, def.ID, via, witness)
	}

	return nil
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
