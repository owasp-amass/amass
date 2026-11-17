// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// OrgForControlledDomain returns an existing Organization already linked to the
// domain as Organization --website--> URL --domain--> FQDN(domain), or nil when
// none is.
//
// Several organization-identity sources (Wikidata, the homepage schema.org
// markup, …) can independently recognize the same company behind one domain. The
// first to run creates the organization and the website chain; the others call
// this so they enrich that one organization instead of each creating a duplicate
// node. It only reduces duplicates — a true simultaneous race (both checking
// before either writes) still falls to the reviewed attribution/duplicates
// merge (ai-design-principles.md principle 10).
func OrgForControlledDomain(sess et.Session, domain string) *dbt.Entity {
	if domain == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(sess.Ctx(), 20*time.Second)
	defer cancel()

	// The apex FQDN exists during an enumeration; CreateAsset is idempotent and
	// returns the existing entity.
	fq, err := sess.DB().CreateAsset(ctx, &oamdns.FQDN{Name: domain})
	if err != nil || fq == nil {
		return nil
	}

	urlEdges, err := sess.DB().IncomingEdges(ctx, fq, time.Time{}, "domain")
	if err != nil {
		return nil
	}
	for _, ue := range urlEdges {
		urlent, err := sess.DB().FindEntityById(ctx, ue.FromEntity.ID)
		if err != nil || urlent == nil {
			continue
		}
		orgEdges, err := sess.DB().IncomingEdges(ctx, urlent, time.Time{}, "website")
		if err != nil {
			continue
		}
		for _, oe := range orgEdges {
			orgent, err := sess.DB().FindEntityById(ctx, oe.FromEntity.ID)
			if err != nil || orgent == nil {
				continue
			}
			if _, ok := orgent.Asset.(*oamorg.Organization); ok {
				return orgent
			}
		}
	}
	return nil
}
