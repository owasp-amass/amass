// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func bountyProgramAsset(id, uniqueID string) graph.Asset {
	handle := uniqueID[strings.Index(uniqueID, ":")+1:]
	return graph.Asset{ID: id, Type: "Account", Key: uniqueID,
		Content: map[string]any{"unique_id": uniqueID, "account_type": BountyAccountType, "username": handle}}
}

func TestBountyAnchor(t *testing.T) {
	ctx := context.Background()
	base := func() graphtest.FakeGraph {
		g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}, EvidenceByID: map[string][]graph.Evidence{}}
		g.Assets["apex"] = graph.Asset{ID: "apex", Type: "FQDN", Key: "acme.com", Content: map[string]any{"name": "acme.com"}}
		g.Assets["h1"] = bountyProgramAsset("h1", "hackerone:acme")
		g.Assets["bc"] = bountyProgramAsset("bc", "bugcrowd:acme")
		return g
	}
	own := []string{"acme.com"}

	g := base()
	if got := BountyAnchor(ctx, g, g.Assets["h1"], g.Assets["apex"], "Acme Corp", own); got != "" {
		t.Errorf("a program that only lists the domain is tied: %q", got)
	}

	g = base()
	g.Assets["cr-h1"] = graph.Asset{ID: "cr-h1", Type: "ContactRecord", Key: "https://hackerone.com/acme",
		Content: map[string]any{"discovered_at": "https://hackerone.com/acme"}}
	g.Assets["site"] = graph.Asset{ID: "site", Type: "URL", Key: "https://www.acme.com/",
		Content: map[string]any{"url": "https://www.acme.com/", "host": "www.acme.com"}}
	g.Links = append(g.Links,
		graph.Relation{ID: "h1-contact", FromID: "h1", ToID: "cr-h1", Label: "contact", Type: "SimpleRelation"},
		graph.Relation{ID: "cr-h1-url", FromID: "cr-h1", ToID: "site", Label: "url", Type: "SimpleRelation"})
	if got := BountyAnchor(ctx, g, g.Assets["h1"], g.Assets["apex"], "Acme Corp", own); !strings.Contains(got, "website") {
		t.Errorf("website anchor = %q", got)
	}

	g = base()
	g.EvidenceByID["h1"] = []graph.Evidence{graphtest.SimpleProp(bountyPropName, "Acme  corp")}
	if got := BountyAnchor(ctx, g, g.Assets["h1"], g.Assets["apex"], "Acme Corp", own); !strings.Contains(got, "named") {
		t.Errorf("name anchor = %q", got)
	}
	if got := BountyAnchor(ctx, g, g.Assets["h1"], g.Assets["apex"], "Acme Corporation", own); got != "" {
		t.Errorf("a different name is tied: %q", got)
	}

	// The Bugcrowd verification record ties a Bugcrowd program only.
	g = base()
	g.EvidenceByID["apex"] = []graph.Evidence{graphtest.TXTRecord("bugcrowd-verification=abc123")}
	if got := BountyAnchor(ctx, g, g.Assets["bc"], g.Assets["apex"], "", own); !strings.Contains(got, "TXT") {
		t.Errorf("TXT anchor = %q", got)
	}
	if got := BountyAnchor(ctx, g, g.Assets["h1"], g.Assets["apex"], "", own); got != "" {
		t.Errorf("a Bugcrowd record tied a HackerOne program: %q", got)
	}

	// The apex's security.txt Policy links the program page.
	g = base()
	g.Assets["file"] = graph.Asset{ID: "file", Type: "URL", Key: "https://acme.com/.well-known/security.txt",
		Content: map[string]any{"url": "https://acme.com/.well-known/security.txt", "host": "acme.com",
			"path": "/.well-known/security.txt"}}
	g.Assets["cr"] = graph.Asset{ID: "cr", Type: "ContactRecord", Key: "https://acme.com/.well-known/security.txt"}
	g.Assets["pol"] = graph.Asset{ID: "pol", Type: "URL", Key: "https://hackerone.com/acme?type=team",
		Content: map[string]any{"url": "https://hackerone.com/acme?type=team", "host": "hackerone.com", "path": "/acme"}}
	g.Assets["other"] = graph.Asset{ID: "other", Type: "URL", Key: "https://hackerone.com/someoneelse",
		Content: map[string]any{"url": "https://hackerone.com/someoneelse", "host": "hackerone.com", "path": "/someoneelse"}}
	g.Links = []graph.Relation{
		{ID: "d", FromID: "file", ToID: "apex", Label: "domain", Type: "SimpleRelation"},
		{ID: "c", FromID: "file", ToID: "cr", Label: "contact", Type: "SimpleRelation"},
		{ID: "s", FromID: "cr", ToID: "other", Label: "url", Type: "SimpleRelation"},
	}
	g.EvidenceByID["s"] = []graph.Evidence{graphtest.SimpleProp(secTxtPropField, "policy")}
	if got := BountyAnchor(ctx, g, g.Assets["h1"], g.Assets["apex"], "", own); got != "" {
		t.Errorf("a link to another program tied it: %q", got)
	}
	g.Links = append(g.Links, graph.Relation{ID: "s2", FromID: "cr", ToID: "pol", Label: "url",
		Type: "SimpleRelation"})
	g.EvidenceByID["s2"] = []graph.Evidence{graphtest.SimpleProp(secTxtPropField, "policy")}
	if got := BountyAnchor(ctx, g, g.Assets["h1"], g.Assets["apex"], "", own); !strings.Contains(got, "security.txt") {
		t.Errorf("security.txt anchor = %q", got)
	}
	// a canonical link is not where a program page is published
	g.EvidenceByID["s2"] = []graph.Evidence{graphtest.SimpleProp(secTxtPropField, "canonical")}
	if got := BountyAnchor(ctx, g, g.Assets["h1"], g.Assets["apex"], "", own); got != "" {
		t.Errorf("a canonical link tied the program: %q", got)
	}
}

func TestPathNamesHandle(t *testing.T) {
	for _, tc := range []struct {
		path, handle string
		want         bool
	}{
		{"/acme", "acme", true},
		{"/engagements/acme/", "acme", true},
		{"/programs/widget/widgetbe/detail", "widget/widgetbe", true},
		{"/programs/widgetbe/detail", "widget/widgetbe", false},
		{"/acme-labs", "acme", false},
		{"", "acme", false},
	} {
		if got := pathNamesHandle(tc.path, tc.handle); got != tc.want {
			t.Errorf("pathNamesHandle(%q, %q) = %v", tc.path, tc.handle, got)
		}
	}
}

// bountyFixture adds to the OWASP fixture a HackerOne program that lists
// www.owasp.org, a sister domain, a name on a cloud hosting domain and an
// address range. named ties the program by its name.
func bountyFixture(named bool) emptyValueGraph {
	g := emptyValueGraph{graphtest.VendorFixture()}
	if g.EvidenceByID == nil {
		g.EvidenceByID = map[string][]graph.Evidence{}
	}
	g.Assets["prog"] = bountyProgramAsset("prog", "hackerone:owasp")
	name := "Some Other Program"
	if named {
		name = "OWASP Foundation"
	}
	g.EvidenceByID["prog"] = []graph.Evidence{graphtest.SimpleProp(bountyPropName, name)}
	for _, n := range []string{"owasp-athletics.com", "owasp.azurewebsites.net"} {
		g.Assets[n] = graph.Asset{ID: n, Type: "FQDN", Key: n, Content: map[string]any{"name": n}}
	}
	g.Assets["nb-prog"] = graph.Asset{ID: "nb-prog", Type: "Netblock", Key: "198.51.100.0/24",
		Content: map[string]any{"cidr": "198.51.100.0/24"}}
	for _, to := range []string{"www.owasp.org", "owasp-athletics.com", "owasp.azurewebsites.net", "nb-prog"} {
		g.Links = append(g.Links, graph.Relation{ID: "prog-in_scope-" + to, FromID: "prog", ToID: to,
			Label: "in_scope", Type: "SimpleRelation"})
	}
	return g
}

func bountyCandidates(t *testing.T, g emptyValueGraph) map[string]GapCandidate {
	t.Helper()
	r, err := SearchOwnershipGaps(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp"])
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]GapCandidate{}
	for _, c := range r.Candidates {
		for _, s := range c.Signals {
			if s.Signal == "bug-bounty-scope" {
				out[c.AssetID] = c
			}
		}
	}
	return out
}

// A program tied to the organization makes the rest of its scope review-only
// candidates; one that is not tied gives nothing.
func TestBountyGapSignals(t *testing.T) {
	got := bountyCandidates(t, bountyFixture(true))
	for _, id := range []string{"owasp-athletics.com", "nb-prog"} {
		c, ok := got[id]
		if !ok {
			t.Errorf("%s is not a bug-bounty candidate: %v", id, got)
			continue
		}
		if c.AutoDecision == GapPropose {
			t.Errorf("%s would be written without review", id)
		}
		for _, s := range c.Signals {
			if s.Signal == "bug-bounty-scope" && s.Kind != DeclarationSignalKind {
				t.Errorf("%s signal kind %q", id, s.Kind)
			}
		}
	}
	if _, ok := got["owasp.azurewebsites.net"]; ok {
		t.Error("a name on a cloud hosting domain was a candidate")
	}

	if got := bountyCandidates(t, bountyFixture(false)); len(got) != 0 {
		t.Errorf("an untied program gave candidates: %v", got)
	}
}

// Declarations, like documents, never help decide an automatic write.
func TestDeclarationSignalsAreReviewOnly(t *testing.T) {
	strong := GapSignal{Signal: "shared_registrant", Kind: SignalIdentity}
	decl := GapSignal{Signal: "bug-bounty-scope", Kind: DeclarationSignalKind}
	if got := WithoutDocumentSignals([]GapSignal{strong, decl}); len(got) != 1 || got[0].Signal != strong.Signal {
		t.Errorf("WithoutDocumentSignals kept %v", got)
	}
	if !isDocumentSignal(GapSignal{Signal: "bug-bounty-scope"}) {
		t.Error("the catalog's declaration signal is not review-only")
	}
}

func TestRelatedDomainsBountyScope(t *testing.T) {
	for _, named := range []bool{true, false} {
		g := relatedDomainsGraph()
		g.EvidenceByID = map[string][]graph.Evidence{}
		g.Assets["prog"] = bountyProgramAsset("prog", "bugcrowd:acme")
		name := "Unrelated"
		if named {
			name = "Acme Corporation"
		}
		g.EvidenceByID["prog"] = []graph.Evidence{graphtest.SimpleProp(bountyPropName, name)}
		g.Assets["fq_acme_shop"] = graph.Asset{ID: "fq_acme_shop", Type: "FQDN", Key: "shop.acme-store.com",
			Content: map[string]any{"name": "shop.acme-store.com"}}
		for _, to := range []string{"fq_acme_net", "fq_acme_shop"} {
			g.Links = append(g.Links, graph.Relation{ID: "in_scope" + to, FromID: "prog", ToID: to,
				Label: "in_scope", Type: "SimpleRelation"})
		}

		r, err := FindRelatedDomains(context.Background(), g, nil, "acme")
		if err != nil {
			t.Fatal(err)
		}
		var found *HorizontalDomain
		for i, d := range r.Domains {
			if d.Domain == "acme-store.com" {
				found = &r.Domains[i]
			}
		}
		switch {
		case !named && found != nil:
			t.Errorf("an untied program related acme-store.com: %+v", found)
		case named && found == nil:
			t.Errorf("the program's domain is not related: %+v", r.Domains)
		case named:
			if len(found.SignalIDs) != 1 || found.SignalIDs[0] != SigBountyScope {
				t.Errorf("acme-store.com %+v: want the bug-bounty signal alone", found)
			}
			if _, strong := HorizontalScore(found.SignalIDs, nil); strong {
				t.Error("a bug-bounty listing alone would expand scope")
			}
		}
	}
}
