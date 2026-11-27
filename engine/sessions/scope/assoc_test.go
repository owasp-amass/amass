// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope_test

import (
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// registeredBy stores a domain whose registration names an organization:
// FQDN --registration--> DomainRecord --registrant_contact--> ContactRecord
// --organization--> Organization.
func registeredBy(t *testing.T, sess *plugintest.Session, domain string, org *oamorg.Organization) (*dbt.Entity, *dbt.Entity) {
	t.Helper()
	fqdn := sess.Asset(t, &oamdns.FQDN{Name: domain})
	rec := sess.Asset(t, &oamreg.DomainRecord{Domain: domain})
	cr := sess.Asset(t, &oamcon.ContactRecord{DiscoveredAt: "https://rdap.example/domain/" + domain})
	orgent := sess.Asset(t, org)
	sess.Edge(t, fqdn, &oamgen.SimpleRelation{Name: "registration"}, rec)
	sess.Edge(t, rec, &oamgen.SimpleRelation{Name: "registrant_contact"}, cr)
	sess.Edge(t, cr, &oamgen.SimpleRelation{Name: "organization"}, orgent)
	return fqdn, orgent
}

func TestIsAssociatedThroughTheRegistrant(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	acme := &oamorg.Organization{ID: "acme:1", Name: "acme"}
	sess.Scope().Add(acme)

	fqdn, orgent := registeredBy(t, sess, "acme-brand.io", &oamorg.Organization{ID: "acme:1", Name: "acme"})
	results, err := sess.Scope().IsAssociated(&et.Association{Submission: fqdn})
	if err != nil || len(results) != 1 {
		t.Fatalf("IsAssociated = %v, %v; want one association", results, err)
	}
	r := results[0]
	if r.BestMatch == nil || r.BestMatch.ID != orgent.ID || r.Confidence != 100 {
		t.Errorf("association = %+v", r)
	}
	// IsAssociated never changes the scope; the association admits the domain
	// as evidence.
	if _, conf := sess.Scope().IsAssetInScope(&oamdns.FQDN{Name: "www.acme-brand.io"}, 0); conf != 0 {
		t.Error("IsAssociated changed the scope")
	}
	d, err := sess.Scope().Admit(&et.AdmissionRequest{Entity: fqdn, Confidence: r.Confidence,
		Evidence: []et.AdmissionEvidence{{Signal: et.SignalAssociation, Strength: et.StrengthStrong,
			Cites: []*dbt.Entity{r.BestMatch}}}})
	if err != nil || d.Outcome != et.Admitted {
		t.Fatalf("Admit = %+v, %v", d, err)
	}
	if _, conf := sess.Scope().IsAssetInScope(&oamdns.FQDN{Name: "www.acme-brand.io"}, 0); conf == 0 {
		t.Error("the admitted domain is not in scope")
	}
}

func TestIsAssociatedRefusesAnOrganizationThatOnlyContainsTheName(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Scope().Add(&oamorg.Organization{ID: "utica:1", Name: "utica"})

	fqdn, _ := registeredBy(t, sess, "uticahospitality.com",
		&oamorg.Organization{ID: "utica hospitality reit:1", Name: "utica hospitality reit"})
	if results, err := sess.Scope().IsAssociated(&et.Association{Submission: fqdn}); err == nil {
		t.Errorf("an unrelated registrant was associated: %+v", results)
	}
	if _, conf := sess.Scope().IsAssetInScope(&oamdns.FQDN{Name: "uticahospitality.com"}, 0); conf > 0 {
		t.Error("the unrelated domain was added to the scope")
	}
}

func TestIsAssociatedRequiresASubmission(t *testing.T) {
	sess := plugintest.NewSession(t)
	if _, err := sess.Scope().IsAssociated(nil); err == nil {
		t.Error("a nil request was accepted")
	}
	if _, err := sess.Scope().IsAssociated(&et.Association{}); err == nil {
		t.Error("a request without a submission was accepted")
	}
}
