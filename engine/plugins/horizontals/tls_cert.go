// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"errors"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

type horTlsCert struct {
	name   string
	plugin *horizPlugin
}

func (h *horTlsCert) Name() string {
	return h.name
}

func (h *horTlsCert) check(e *et.Event) error {
	c, ok := e.Entity.Asset.(*oamcert.TLSCertificate)
	if !ok {
		return errors.New("failed to cast the TLSCertificate asset")
	}

	// check if scope expansion is allowed
	if e.Session.Config().Rigid {
		return nil
	}

	if orgs, err := h.lookup(e.Session, e.Entity); err == nil && len(orgs) > 0 {
		h.process(e, c, orgs)
	}
	return nil
}

func (h *horTlsCert) lookup(sess et.Session, tlsent *dbt.Entity) ([]*dbt.Entity, error) {
	cr, err := h.plugin.getContactRecord(sess, tlsent, "subject_contact")
	if err != nil {
		return nil, errors.New("failed to obtain the subject contact record")
	}

	orgs, err := h.plugin.getContactRecordOrganizations(sess, cr)
	if err != nil {
		return nil, errors.New("failed to obtain the subject organizations")
	}

	return orgs, nil
}

func (h *horTlsCert) process(e *et.Event, c *oamcert.TLSCertificate, orgs []*dbt.Entity) {
	// check if the TLS certificate subject common name is in scope
	if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: c.SubjectCommonName}, 0); conf > 0 {
		return
	}

	var found bool
	for _, o := range orgs {
		if h.plugin.isEntityInScope(e.Session, o) {
			found = true
			break
		}
	}

	if found {
		// the TLS certificate subject common name and related
		// organizations should be added to the scope and reviewed
		if fqdn := h.registeredFQDN(e.Session, c); fqdn != nil {
			h.plugin.enqueueIfOutOfScope(e.Session, fqdn)
		}
		for _, o := range orgs {
			h.plugin.enqueueIfOutOfScope(e.Session, o)
		}
	}
}

func (h *horTlsCert) registeredFQDN(sess et.Session, c *oamcert.TLSCertificate) *dbt.Entity {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	ents, err := sess.DB().FindEntitiesByContent(ctx, oam.FQDN, time.Time{}, 1, dbt.ContentFilters{
		"name": c.SubjectCommonName,
	})
	if err != nil || len(ents) != 1 {
		return nil
	}
	domain := ents[0]

	// follow the node relations back to the registered domain name
	for {
		apex := h.getZoneApexFQDN(sess, domain)
		if apex == nil || apex.ID == domain.ID {
			break
		}
		domain = apex
	}

	return domain
}

func (h *horTlsCert) getZoneApexFQDN(sess et.Session, fqdn *dbt.Entity) *dbt.Entity {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	if edges, err := sess.DB().IncomingEdges(ctx, fqdn, time.Time{}, "node"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if from, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil {
				return from
			}
		}
	}
	return nil
}
