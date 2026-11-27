// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"net/url"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// signalsFrom collects the signals that one controlled asset gives.
func (g *gapSearch) signalsFrom(cur graph.Asset) error {
	steps, err := g.w.steps(cur)
	if err != nil {
		return err
	}
	for _, s := range steps {
		if _, mine := g.owned[s.other.ID]; mine {
			continue
		}

		hop := WitnessOf(s.edge, cur, s.other)
		via := s.other.Type + " " + s.edge.Label + " " + cur.Type
		switch {
		case !s.forward && g.reverseDNS(s):
			// Its reverse DNS names one of the subject's hosts.
			if err := g.reverseDNSSignals(cur, s, hop); err != nil {
				return err
			}
		case !s.forward && g.selfHostedDNS(s):
			// Its name or mail servers are the subject's own hosts.
			if rr := rrTypeName(relationRRType(s.edge)); rr != "" {
				via = s.other.Type + " " + rr + " " + cur.Type
			}

			g.add(s.other, sigSelfHostedDNS, via, append(g.pathTo(cur.ID), hop))
		case s.attr == graph.AttrInfrastructure && !s.forward:
			// Something outside the footprint depends on a controlled asset,
			// unless that asset is a provider's shared range or a private
			// address, which unrelated parties depend on too.
			shared, err := g.sharedAddress(cur)
			if err != nil {
				return err
			}
			if !shared {
				g.add(s.other, sigHosting, via, append(g.pathTo(cur.ID), hop))
			}
		case s.attr == "attribute" && s.forward && cur.Type == "ContactRecord":
			if err := g.identity(cur, s, hop); err != nil {
				return err
			}
		case s.attr == graph.AttrShared && !s.forward:
			if err := g.colisting(cur, s.other, hop); err != nil {
				return err
			}
		}
	}

	return nil
}

// identity follows an attribute value (a phone, address, email or other
// identifier) of a controlled registration contact to the other contact
// records that carry the same value. Other assets' attributes (a service's
// fingerprints) are not registrant details: the fingerprint signals judge
// them.
//
// A value that identifies no one gives no signal: a redaction or privacy
// placeholder, or a value carried by more contact records outside the
// footprint than the hub limit.
func (g *gapSearch) identity(cur graph.Asset, s step, hop graph.WitnessEdge) error {
	value := s.other
	if graph.IsPlaceholder(value) {
		return nil
	}

	// a registrar's, abuse desk's or certificate issuer's details are that
	// party's, not the subject's
	if third, err := g.thirdPartyContact(cur); err != nil || third {
		return err
	}

	steps, err := g.w.steps(value)
	if err != nil {
		return err
	}

	var holders []step
	for _, t := range steps {
		if !t.forward && t.attr == "attribute" {
			holders = append(holders, t)
		}
	}
	var others []step
	for _, t := range g.outsideSteps(holders) {
		if t.other.Type == "ContactRecord" {
			others = append(others, t)
		}
	}
	// a value held by unusually many other contacts for its kind is a
	// provider's
	if g.hub(s.edge.Label, "in", GapMaxShared).over(graph.AssetLabel(value), len(others), false) {
		return nil
	}

	via := cur.Type + " " + s.edge.Label + " " + value.Type
	sources := g.ownSources(value, holders)
	for _, t := range others {
		other := t.other
		if third, err := g.thirdPartyContact(other); err != nil {
			return err
		} else if third {
			continue
		}

		witness := append(append(g.pathTo(cur.ID), hop), WitnessOf(t.edge, value, other))
		g.add(other, sigSharedRegistrant, via, witness)
		if sources >= 2 {
			// the subject's number in independent sources is corroborated as
			// its own, so the match counts twice
			g.add(other, sigSharedRegistrant, fmt.Sprintf("%s, the organization's in %d sources", via, sources), witness)
		}
	}

	return nil
}

// thirdPartyContact reports whether a is a contact record named only as
// another party's: a domain's registrar, a network's abuse desk or a
// certificate's issuer (semantics.ThirdPartyContact).
func (g *gapSearch) thirdPartyContact(a graph.Asset) (bool, error) {
	if a.Type != "ContactRecord" {
		return false, nil
	}

	steps, err := g.w.steps(a)
	if err != nil {
		return false, err
	}

	var labels []string
	for _, t := range steps {
		if !t.forward {
			labels = append(labels, t.edge.Label)
		}
	}
	return semantics.ThirdPartyContact(labels), nil
}

// ownSources counts the independent sources that give a phone number for the
// subject: the distinct registered domains of the subject's own contact
// records that hold it (a registration record, OpenStreetMap, SEC filings).
// Other values count none.
func (g *gapSearch) ownSources(value graph.Asset, holders []step) int {
	if value.Type != "Phone" {
		return 0
	}

	seen := map[string]bool{}
	for _, t := range holders {
		if _, mine := g.owned[t.other.ID]; !mine || t.other.Type != "ContactRecord" {
			continue
		}
		if u, err := url.Parse(graph.AssetLabel(t.other)); err == nil && u.Hostname() != "" {
			source := graph.RegisteredDomain(u.Hostname())
			if source == "" {
				source = u.Hostname()
			}
			seen[source] = true
		}
	}
	return len(seen)
}

// colisting follows a shared asset (a certificate listing a controlled
// name) to the other assets it lists, unless it lists too many to signal
// anything (a provider's multi-tenant certificate).
func (g *gapSearch) colisting(cur, shared graph.Asset, hop graph.WitnessEdge) error {
	// a CDN's certificate lists its customers side by side
	if managed, err := g.providerManagedCertificate(shared); err != nil || managed {
		return err
	}

	steps, err := g.w.steps(shared)
	if err != nil {
		return err
	}

	var listed []step
	for _, t := range steps {
		if t.forward && t.attr == graph.AttrShared {
			listed = append(listed, t)
		}
	}
	// the names it lists besides the subject's own
	listed = g.outsideSteps(listed)
	if g.hub(hop.Label, "out", gapMaxColisted).over(graph.AssetLabel(shared), len(listed), false) {
		return nil
	}
	for _, t := range listed {
		witness := append(append(g.pathTo(cur.ID), hop), WitnessOf(t.edge, shared, t.other))
		g.add(t.other, sigColisting, shared.Type+" "+t.edge.Label, witness)
	}

	return nil
}
