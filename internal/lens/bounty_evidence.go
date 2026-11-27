// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	"github.com/owasp-amass/amass/v5/internal/semantics/cloudranges"
)

// Bug-bounty program scopes (engine/plugins/bounty) are an organization
// declaring the assets it is responsible for. A program's listing counts as
// ownership evidence only once the program is tied to the organization
// (BountyAnchor), and it is review-only: DeclarationSignalKind signals never
// cause or help cause an automatic write (WithoutDocumentSignals).

// DeclarationSignalKind is the kind of the signals that come from an
// organization's own public declaration of its assets, such as a bug-bounty
// program's scope. Like document signals they raise a candidate to review but
// are never decided on automatically.
const DeclarationSignalKind = "declaration"

// matchBountyScope is the matcher of the bug-bounty-scope ownership signal.
const matchBountyScope = "bounty_program_scope"

// BountyAccountType is the account_type of a bug-bounty program Account.
const BountyAccountType = "bug_bounty_program"

// bountyPropName is the program Account property the bounty plugin stores
// for the program's name. Its website is the Account's ContactRecord URL.
const bountyPropName = "bounty_program_name"

// isBountyProgram reports whether a is a bug-bounty program Account.
func isBountyProgram(a graph.Asset) bool {
	return a.Type == "Account" && graph.ContentString(a, "account_type") == BountyAccountType
}

// bountyProgramID splits a program's unique ID, <platform>:<handle>.
func bountyProgramID(id string) (semantics.BountyPlatform, string, bool) {
	key, handle, ok := strings.Cut(id, ":")
	if !ok || handle == "" {
		return semantics.BountyPlatform{}, "", false
	}
	p, ok := semantics.BountyPlatformByKey(key)
	return p, strings.ToLower(handle), ok
}

// BountyAnchor reports what ties a bug-bounty program to the organization,
// or "" when nothing does. apex is the organization's registered domain the
// program lists a name under; ownDomains are its registered domains. In the
// order checked:
//   - the program's website is in the organization's namespace;
//   - the program's name is exactly the organization's name;
//   - the apex carries the platform's domain verification TXT record;
//   - the apex's security.txt links the program's page.
//
// A program that merely lists the organization's names is not tied to it: a
// program can list a partner's or a vendor's asset.
func BountyAnchor(ctx context.Context, gr graph.Graph, program, apex graph.Asset, orgName string,
	ownDomains []string) string {
	plat, handle, ok := bountyProgramID(graph.ContentString(program, "unique_id"))
	if !ok {
		return ""
	}

	for _, site := range contactTargets(ctx, gr, program.ID, "contact", "url") {
		host := graph.ContentString(site, "host")
		for _, d := range ownDomains {
			if host != "" && HostWithin(host, d) {
				return "the program's website " + host + " is the organization's"
			}
		}
	}
	if ev, err := gr.Evidence(ctx, program.ID, 50); err == nil {
		if fold := docFold(orgName); fold != "" {
			for _, n := range propertyValues(ev, bountyPropName) {
				if docFold(n) == fold {
					return "the program is named " + n
				}
			}
		}
	}

	name := graph.FQDNName(apex)
	if apex.ID == "" || name == "" {
		return ""
	}
	if plat.TXTPrefix != "" {
		if txts, err := graph.TXTValues(ctx, gr, apex.ID); err == nil {
			for _, t := range txts {
				if hasPrefixFold(strings.TrimSpace(t), plat.TXTPrefix) {
					return "a " + strings.TrimSuffix(plat.TXTPrefix, "=") + " TXT record on " + name
				}
			}
		}
	}
	if link := securityTxtProgramLink(ctx, gr, apex.ID, plat, handle); link != "" {
		return name + "'s security.txt links " + link
	}
	return ""
}

// securityTxtProgramFields are the security.txt fields whose URL can be the
// program's page; "" is a Contact entry.
var securityTxtProgramFields = []string{"policy", "acknowledgments", "hiring", ""}

// securityTxtProgramLink returns the URL in the apex's security.txt (a
// Policy, Acknowledgments or Hiring field, or a Contact URL) that is the
// program's page, or "" when there is none.
func securityTxtProgramLink(ctx context.Context, gr graph.Graph, apexID string, plat semantics.BountyPlatform,
	handle string) string {
	apex, err := gr.GetAsset(ctx, apexID)
	if err != nil {
		return ""
	}
	for _, st := range readSecurityTxt(ctx, gr, apex) {
		for _, u := range st.urls {
			if !slices.Contains(securityTxtProgramFields, u.field) {
				continue
			}
			if plat.OwnsHost(graph.ContentString(u.url, "host")) &&
				pathNamesHandle(graph.ContentString(u.url, "path"), handle) {
				return graph.AssetLabel(u.url)
			}
		}
	}
	return ""
}

// pathNamesHandle reports whether every part of a program handle (a company
// and program handle for some platforms) is a segment of the URL path.
func pathNamesHandle(path, handle string) bool {
	segs := map[string]bool{}
	for _, s := range strings.Split(strings.ToLower(path), "/") {
		if s != "" {
			segs[s] = true
		}
	}
	parts := strings.Split(handle, "/")
	for _, p := range parts {
		if p == "" || !segs[p] {
			return false
		}
	}
	return len(parts) > 0
}

// webHost returns the host of a website value, a URL or a bare host name.
func webHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}

// bountySkipHost reports whether a host a program lists is shared
// infrastructure that says nothing about the program's owner: a name under a
// cloud provider's hosting domain or a bug-bounty platform's own site.
func bountySkipHost(host string) bool {
	if _, ok := cloudranges.ProviderByDomain(host); ok {
		return true
	}
	for _, p := range semantics.BountyPlatforms() {
		if p.OwnsHost(host) {
			return true
		}
	}
	return false
}

// bountySignals finds the assets a bug-bounty program lists beside one of
// the organization's names, when the program is tied to the organization.
// Every owned name is checked, since a program can list a host (www.example.com)
// rather than its registered domain; each program is read once per search.
func (g *gapSearch) bountySignals(owned graph.Asset) error {
	def, ok := firstSignal(matchBountyScope)
	if !ok {
		return nil
	}
	steps, err := g.w.steps(owned)
	if err != nil {
		return err
	}

	for _, s := range steps {
		if s.forward || s.edge.Label != "in_scope" || !isBountyProgram(s.other) {
			continue
		}
		if g.bountyPrograms == nil {
			g.bountyPrograms = map[string]bool{}
		}
		if g.bountyPrograms[s.other.ID] {
			continue
		}
		g.bountyPrograms[s.other.ID] = true
		if !g.read() {
			return nil
		}

		apex := g.ownedApexOf(owned)
		anchor := BountyAnchor(g.w.ctx, g.w.graph, s.other, apex, graph.ContentString(g.owner, "name"), g.domains)
		if anchor == "" {
			continue
		}

		listed := WitnessOf(s.edge, s.other, owned)
		tie := matched(apex, s.other, "bounty_program_anchor", anchor)
		scope, err := g.w.steps(s.other)
		if err != nil {
			return err
		}
		for _, t := range scope {
			if !t.forward || t.edge.Label != "in_scope" || t.other.ID == owned.ID {
				continue
			}
			if t.other.Type == "FQDN" && bountySkipHost(graph.FQDNName(t.other)) {
				continue
			}
			witness := append(g.pathTo(owned.ID), listed, tie, WitnessOf(t.edge, s.other, t.other))
			g.add(t.other, def.ID, "bug-bounty program scope "+t.other.Type, witness)
		}
	}
	return nil
}

// ownedApexOf returns the owned registered domain a controlled name is
// under, or the name itself when that domain is not stored.
func (g *gapSearch) ownedApexOf(a graph.Asset) graph.Asset {
	name := graph.FQDNName(a)
	dom := graph.RegisteredDomain(name)
	if dom == "" || dom == name {
		return a
	}
	for _, o := range g.owned {
		if o.Type == "FQDN" && graph.FQDNName(o) == dom {
			return o
		}
	}
	return a
}

// bountyScopePivot finds the other registered domains a bug-bounty program
// lists beside one of the organization's names, when the program is tied to
// the organization: the organization's declared assets. It is a supporting
// horizontal signal, so it sends a domain to review and never expands scope
// on its own.
func bountyScopePivot(ctx context.Context, g graph.Graph, orgName string, ownApexes []string,
	add func(string, string, string, ...graph.WitnessEdge)) {
	apexes := map[string]graph.Asset{}
	var ownDomains []string
	for _, id := range ownApexes {
		if a, err := g.GetAsset(ctx, id); err == nil && graph.FQDNName(a) != "" {
			apexes[id] = a
			ownDomains = append(ownDomains, graph.FQDNName(a))
		}
	}

	seen := map[string]bool{}
	for _, apexID := range ownApexes {
		apex, ok := apexes[apexID]
		if !ok {
			continue
		}
		hosts := []string{apexID}
		if nodes, err := g.Edges(ctx, apexID, "out", "node", time.Time{}); err == nil {
			for _, n := range nodes {
				hosts = append(hosts, n.ToID)
			}
		}

		for _, hostID := range hosts {
			listings, err := g.Edges(ctx, hostID, "in", "in_scope", time.Time{})
			if err != nil {
				continue
			}
			for _, le := range listings {
				if seen[le.FromID] {
					continue
				}
				prog, err := g.GetAsset(ctx, le.FromID)
				if err != nil || !isBountyProgram(prog) {
					continue
				}
				seen[le.FromID] = true
				if BountyAnchor(ctx, g, prog, apex, orgName, ownDomains) == "" {
					continue
				}

				scope, err := g.Edges(ctx, prog.ID, "out", "in_scope", time.Time{})
				if err != nil {
					continue
				}
				listedW := graph.WitnessEdge{EdgeID: le.ID, Label: "in_scope", RelationType: le.Type,
					FromID: le.FromID, FromType: "Account", ToID: le.ToID, ToType: "FQDN"}
				for _, se := range scope {
					a, err := g.GetAsset(ctx, se.ToID)
					if err != nil || a.Type != "FQDN" {
						continue
					}
					name := graph.FQDNName(a)
					dom := graph.RegisteredDomain(name)
					if dom == "" || bountySkipHost(name) {
						continue
					}
					scopeW := graph.WitnessEdge{EdgeID: se.ID, Label: "in_scope", RelationType: se.Type,
						FromID: se.FromID, FromType: "Account", ToID: se.ToID, ToType: "FQDN"}
					add(dom, SigBountyScope, "listed by the organization's bug-bounty program", listedW, scopeW)
				}
			}
		}
	}
}
