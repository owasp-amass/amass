// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// strongContributions is a graph that lets contributions be strong
// evidence.
type strongContributions struct{ graphtest.FakeGraph }

func (strongContributions) ContributionsStrong() bool { return true }

func contributedEdge(g graphtest.FakeGraph, id string, sources ...string) {
	if g.EvidenceByID == nil {
		return
	}
	for _, s := range sources {
		g.EvidenceByID[id] = append(g.EvidenceByID[id], graph.Evidence{ID: id + s, SubjectID: id, SourceID: s,
			Kind: "SourceProperty"})
	}
}

// A record counts as contributed only when every source it has is an
// assistant's. A way rests on contributions when any link it needs does; a
// signal does when every way does.
func TestContributionJudge(t *testing.T) {
	g := graphtest.FakeGraph{EvidenceByID: map[string][]graph.Evidence{}}
	contributedEdge(g, "e1", "amass-ai:claude")
	contributedEdge(g, "e2", "amass-ai:claude", "DNS")
	contributedEdge(g, "e3", "DNS")
	way := func(ids ...string) []evidenceLink {
		var w []graph.WitnessEdge
		for _, id := range ids {
			w = append(w, graph.WitnessEdge{EdgeID: id})
		}
		return witnessSupport(w)
	}

	j := newContributionJudge(context.Background(), g)
	for name, c := range map[string]struct {
		support signalSupport
		want    bool
	}{
		"contributed edge":              {signalSupport{way("e1")}, true},
		"chain with a contributed link": {signalSupport{way("e3", "e1")}, true},
		"edge a collector also saw":     {signalSupport{way("e2")}, false},
		"collected edge":                {signalSupport{way("e3")}, false},
		"untagged edge":                 {signalSupport{way("untagged")}, false},
		"no stored witness":             {signalSupport{way()}, false},
		"a collected way too":           {signalSupport{way("e1"), way("e3")}, false},
		"every way contributed":         {signalSupport{way("e1"), way("e3", "e1")}, true},
		"contributed entity":            {signalSupport{{{entities: []string{"e1"}}}}, true},
		"no support":                    {nil, false},
		"a link of either edge":         {signalSupport{{{edges: []string{"e1", "e3"}}}}, false},
	} {
		if got := j.contributed(c.support); got != c.want {
			t.Errorf("%s: contributed = %v, want %v", name, got, c.want)
		}
	}

	if newContributionJudge(context.Background(), strongContributions{g}).contributed(signalSupport{way("e1")}) {
		t.Error("a graph that lets contributions be strong judged one contributed")
	}
}

// A strong ownership signal that rests on contributions counts as
// supporting: it cannot propose ownership.
func TestContributedSignalsCannotProposeOwnership(t *testing.T) {
	a := GapSignal{Signal: "shared-registrant-details", Kind: SignalIdentity, Via: "a"}
	b := GapSignal{Signal: "shared-registrant-details", Kind: SignalIdentity, Via: "b"}
	if _, d := ScoreGap([]GapSignal{a, b}, true); d != GapPropose {
		t.Fatalf("collected strong signals decided %q", d)
	}

	a.Contributed, b.Contributed = true, true
	score, d := ScoreGap([]GapSignal{a, b}, true)
	if d == GapPropose {
		t.Error("contributed signals proposed ownership")
	}
	if score == 0 {
		t.Error("contributed signals lost their weight")
	}
}

// A related domain only a contribution ties to the organization by a strong
// signal needs review, unless contributions may be strong evidence.
func TestContributedRelatedDomainNeedsReview(t *testing.T) {
	g := relatedDomainsGraph()
	g.EvidenceByID = map[string][]graph.Evidence{}
	// acme.org is tied only by the official website: Organization
	// --website--> URL --domain--> FQDN, both contributed.
	contributedEdge(g, "websiteacmeurl_acme_org", "amass-ai:claude")
	contributedEdge(g, "domainurl_acme_orgfq_acme_org", "amass-ai:claude")

	find := func(g graph.Graph) (HorizontalDomain, bool) {
		t.Helper()
		r, err := FindRelatedDomains(context.Background(), g, nil, "acme")
		if err != nil {
			t.Fatal(err)
		}
		expand, _ := HorizontalExpansion(r)
		for _, d := range r.Domains {
			if d.Domain == "acme.org" {
				return d, slices.ContainsFunc(expand, func(e HorizontalDomain) bool { return e.Domain == d.Domain })
			}
		}
		t.Fatal("acme.org was not found")
		return HorizontalDomain{}, false
	}

	d, expands := find(g)
	if expands || !slices.Contains(d.ContributedSignals, SigOfficialWebsite) {
		t.Errorf("contributed acme.org = %+v, expands %v", d, expands)
	}
	if d.Confidence == 0 {
		t.Error("the contributed signal lost its weight")
	}

	if d, expands := find(strongContributions{g}); !expands || len(d.ContributedSignals) != 0 {
		t.Errorf("with strong contributions acme.org = %+v, expands %v", d, expands)
	}

	// A collector also recorded the website, but the URL's domain is still
	// only contributed: the chain rests on it.
	contributedEdge(g, "websiteacmeurl_acme_org", "GLEIF")
	if d, expands := find(g); expands {
		t.Errorf("acme.org through a contributed link = %+v, expands", d)
	}

	// Every link was collected too: the signal is strong again.
	contributedEdge(g, "domainurl_acme_orgfq_acme_org", "DNS")
	if d, expands := find(g); !expands {
		t.Errorf("collected acme.org = %+v, expands %v", d, expands)
	}
}

// A duplicate pair matched only by a contributed identifier, contact record
// or registration is never merged automatically; matched by collected
// records it is.
func TestContributedDuplicateSignalsDoNotMerge(t *testing.T) {
	profile := func(id, lei, cr string) *orgProfile {
		p := &orgProfile{asset: graph.Asset{ID: id, Type: "Organization"}, brands: map[string]bool{},
			ids: map[string]map[string]bool{}, contacts: map[string]bool{cr: true}, locations: map[string]bool{},
			addresses: map[string]bool{}, related: map[string]bool{}, parents: map[string]bool{},
			idEdges: map[string][]string{}, contactEdges: map[string][]string{cr: {id + "-cr"}},
			jurisdiction: "US-DE", registration: "123"}
		p.addName("Acme Corporation")
		if t, v, ok := p.addIdentifier("lei", lei); ok {
			p.idEdges[t+"\x00"+v] = []string{id + "-lei"}
		}
		return p
	}
	a, b := profile("a", "LEI1", "cr1"), profile("b", "LEI1", "cr1")

	g := graphtest.FakeGraph{EvidenceByID: map[string][]graph.Evidence{}}
	for _, id := range []string{"a", "b", "a-lei", "b-lei", "a-cr", "b-cr"} {
		contributedEdge(g, id, "GLEIF")
	}
	merge := func() (bool, []GapSignal) {
		signals := pairSignals(a, b)
		newContributionJudge(context.Background(), g).mark(signals, DuplicateSignal)
		return AutoMergeable(signals), signals
	}
	if ok, signals := merge(); !ok {
		t.Fatalf("collected duplicates not mergeable: %+v", signals)
	}

	// Only an assistant recorded b, its identifier and its contact record.
	for _, id := range []string{"b", "b-lei", "b-cr"} {
		g.EvidenceByID[id] = nil
		contributedEdge(g, id, "amass-ai:claude")
	}
	ok, signals := merge()
	if ok {
		t.Errorf("contributed duplicates are mergeable: %+v", signals)
	}
	for _, s := range signals {
		if def, _ := DuplicateSignal(s.Signal); def.Strength == StrengthStrong && !s.Contributed {
			t.Errorf("%s is still strong", s.Signal)
		}
	}
}
