// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/classify"
	"github.com/owasp-amass/amass/v5/internal/lens"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// transforms sets the session's transformations: Organization -> all enabled so
// the TTL guard resolves, and FQDN -> all at confidence 0 so widenScopeToDomain
// adds to scope but skips the backlog enqueue (plugintest has no backlog).
func transforms(sess *plugintest.Session) {
	sess.Config().Transformations = map[string]*config.Transformation{
		"organization->all": {From: "organization", To: "all", TTL: 1440, Confidence: 100},
		"fqdn->all":         {From: "fqdn", To: "all", TTL: 1440, Confidence: 0},
	}
}

func inScope(sess *plugintest.Session, name string) bool {
	_, conf := sess.Scope().IsAssetInScope(&oamdns.FQDN{Name: name}, 0)
	return conf > 0
}

func TestWidenScopeToDomain(t *testing.T) {
	sess := plugintest.NewSession(t)
	transforms(sess)
	h := NewHorizontals().(*horizPlugin)
	sess.Asset(t, &oamdns.FQDN{Name: "example.com"})

	if !h.widenScopeToDomain(sess.Ctx(), sess, "example.com") {
		t.Fatal("a known, out-of-scope domain should be added to scope")
	}
	if !inScope(sess, "example.com") {
		t.Error("example.com should now be in scope")
	}
	if h.widenScopeToDomain(sess.Ctx(), sess, "example.com") {
		t.Error("a domain already in scope should not be reported as newly added")
	}
	if h.widenScopeToDomain(sess.Ctx(), sess, "never-stored.com") {
		t.Error("a domain with no stored FQDN should not be added")
	}
}

func TestExpandRelatedDomainsRigid(t *testing.T) {
	sess := plugintest.NewSession(t)
	transforms(sess)
	sess.Config().Rigid = true
	h := NewHorizontals().(*horizPlugin)

	org := sess.Asset(t, &oamorg.Organization{ID: "org-1", Name: "Acme Corporation"})
	fq := sess.Asset(t, &oamdns.FQDN{Name: "acme.com"})
	_ = fq

	h.expandRelatedDomains(&et.Event{Session: sess, Entity: org}, org)
	if inScope(sess, "acme.com") {
		t.Error("a rigid run must not widen scope")
	}
}

func TestExpandRelatedDomainsWidensScope(t *testing.T) {
	sess := plugintest.NewSession(t)
	transforms(sess)
	// Attribution off: expansion still widens scope, it just does not journal,
	// which keeps the test independent of the journal path.
	sess.Config().AI = &config.AISettings{Attribution: config.AttributionOff}
	h := NewHorizontals().(*horizPlugin)

	org := sess.Asset(t, &oamorg.Organization{ID: "org-1", Name: "Acme Corporation"})
	cr := sess.Asset(t, &oamcon.ContactRecord{DiscoveredAt: "https://rdap.example/domain/acme.com"})
	sess.Edge(t, cr, link("organization"), org)

	for _, d := range []string{"acme.com", "acme.net"} {
		dr := sess.Asset(t, &oamreg.DomainRecord{Domain: d, Name: d, ID: "D-" + d})
		sess.Edge(t, dr, link("registrant_contact"), cr)
		sess.Asset(t, &oamdns.FQDN{Name: d})
	}

	h.expandRelatedDomains(&et.Event{Session: sess, Entity: org}, org)

	// Both apex domains share the registrant organization (a strong signal), so
	// both are added to scope by the scored expansion.
	for _, d := range []string{"acme.com", "acme.net"} {
		if !inScope(sess, d) {
			t.Errorf("%s should have been added to scope by the scored expansion", d)
		}
	}

	// A privacy-proxy organization is never correlated on, so a second run for a
	// proxy org adds nothing.
	proxy := sess.Asset(t, &oamorg.Organization{ID: "org-2", Name: "Domains By Proxy, LLC"})
	pcr := sess.Asset(t, &oamcon.ContactRecord{DiscoveredAt: "https://rdap.example/domain/stranger.com"})
	sess.Edge(t, pcr, link("organization"), proxy)
	pdr := sess.Asset(t, &oamreg.DomainRecord{Domain: "stranger.com", Name: "stranger.com", ID: "D-stranger"})
	sess.Edge(t, pdr, link("registrant_contact"), pcr)
	sess.Asset(t, &oamdns.FQDN{Name: "stranger.com"})

	h.expandRelatedDomains(&et.Event{Session: sess, Entity: proxy}, proxy)
	if inScope(sess, "stranger.com") {
		t.Error("a privacy-proxy organization must not widen scope")
	}
}

func TestHorizontalScorerLoads(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.Config().Dir = t.TempDir()
	h := NewHorizontals().(*horizPlugin)

	_, journalPath, err := sess.Config().AIAttribution(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	modelPath := ai.HorizontalModelPath(journalPath)
	if err := os.MkdirAll(filepath.Dir(modelPath), 0o755); err != nil {
		t.Fatal(err)
	}
	model := classify.LinearModel{
		ModelID: "test-horiz", Task: ai.HorizontalTask, FeatureVersion: ai.HorizontalFeatureVersion,
		SkipThreshold: 0.7, ReviewThreshold: 0.7,
		Classes: []classify.LinearClass{
			{Label: "unrelated", Bias: 0, Weights: map[string]float64{"signal:" + lens.SigSharedNameServer: 0}},
			{Label: "potential_relation", Bias: 0, Weights: map[string]float64{"signal:" + lens.SigSharedNameServer: 5}},
		},
	}
	data, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modelPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	s := h.horizontalScorer(sess)
	if s == nil || s.ModelName() != "test-horiz" {
		t.Fatalf("horizontalScorer should load the model, got %v", s)
	}
	if h.horizontalScorer(sess) != s {
		t.Error("the scorer should be cached, not reloaded")
	}

	// A different session with attribution off gets no scorer.
	off := plugintest.NewSession(t)
	off.Config().AI = &config.AISettings{Attribution: config.AttributionOff}
	if NewHorizontals().(*horizPlugin).horizontalScorer(off) != nil {
		t.Error("attribution off should yield no scorer")
	}
}

func TestExpandRelatedInfrastructureWidensScope(t *testing.T) {
	sess := plugintest.NewSession(t)
	transforms(sess)
	sess.Config().AI = &config.AISettings{Attribution: config.AttributionOff}
	h := NewHorizontals().(*horizPlugin)

	org := sess.Asset(t, &oamorg.Organization{ID: "org-1", Name: "Acme Corporation"})
	cr := sess.Asset(t, &oamcon.ContactRecord{DiscoveredAt: "https://rdap.example/ip/acme"})
	sess.Edge(t, cr, link("organization"), org)

	// A netblock registered to the org (strong), with its Netblock asset.
	nbCIDR := netip.MustParsePrefix("192.0.2.0/24")
	ipr := sess.Asset(t, &oamreg.IPNetRecord{CIDR: nbCIDR, Handle: "NET-192-0-2-0-1", Type: "IPv4",
		StartAddress: netip.MustParseAddr("192.0.2.0"), EndAddress: netip.MustParseAddr("192.0.2.255"), Name: "ACME"})
	sess.Edge(t, ipr, link("registrant"), cr)
	sess.Asset(t, &oamnet.Netblock{CIDR: nbCIDR, Type: "IPv4"})

	// An AS registered to the org (strong), plus a prefix it announces
	// (supporting — review only).
	asr := sess.Asset(t, &oamreg.AutnumRecord{Number: 64500, Handle: "AS64500", Name: "ACME"})
	sess.Edge(t, asr, link("registrant"), cr)
	as := sess.Asset(t, &oamnet.AutonomousSystem{Number: 64500})
	sess.Edge(t, as, link("registration"), asr)
	annCIDR := netip.MustParsePrefix("203.0.113.0/24")
	ann := sess.Asset(t, &oamnet.Netblock{CIDR: annCIDR, Type: "IPv4"})
	sess.Edge(t, as, link("announces"), ann)

	h.expandRelatedInfrastructure(&et.Event{Session: sess, Entity: org}, org)

	if _, c := sess.Scope().IsAssetInScope(&oamnet.Netblock{CIDR: nbCIDR, Type: "IPv4"}, 0); c <= 0 {
		t.Error("the RIR-registered netblock should be added to scope")
	}
	if _, c := sess.Scope().IsAssetInScope(&oamnet.AutonomousSystem{Number: 64500}, 0); c <= 0 {
		t.Error("the RIR-registered AS should be added to scope")
	}
	// The announced-only prefix is a supporting signal, so it must not auto-expand.
	if _, c := sess.Scope().IsAssetInScope(&oamnet.Netblock{CIDR: annCIDR, Type: "IPv4"}, 0); c > 0 {
		t.Error("an announced-only netblock must not auto-expand scope")
	}
}

func TestJournalFor(t *testing.T) {
	sess := plugintest.NewSession(t)
	h := NewHorizontals().(*horizPlugin)

	// Default settings leave attribution enabled, so a journal is configured.
	if h.journalFor(sess) == nil {
		t.Error("journalFor should return a journal when attribution is enabled")
	}
	// With attribution off there is no journal.
	sess.Config().AI = &config.AISettings{Attribution: config.AttributionOff}
	if h.journalFor(sess) != nil {
		t.Error("journalFor should return nil when attribution is off")
	}
}
