// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"testing"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
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
