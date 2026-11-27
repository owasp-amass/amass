// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"errors"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
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

	// the expansion policy may admit nothing at all
	if !e.Session.Config().Widens() {
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
	// a certificate may name its subject only in its alternative names
	if c.SubjectCommonName == "" {
		return
	}
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
		// The certificate's apex domains are added through the scored
		// horizontal expansion for each in-scope subject organization (which
		// includes them via the certificate-subject signal), rather than a
		// direct single-signal enqueue, so the scope change is scored and
		// journaled.
		for _, o := range orgs {
			if h.plugin.isEntityInScope(e.Session, o) {
				h.plugin.expandRelatedDomains(e, o)
			}
		}
		for _, o := range orgs {
			h.plugin.admitIfOutOfScope(e.Session, o, et.SignalSharedContactRecord)
		}
	}
}
