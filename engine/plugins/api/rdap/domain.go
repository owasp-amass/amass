// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"cmp"
	"strings"

	"github.com/openrdap/rdap"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// domain is the RDAP discovery handler: it turns a registered domain name
// into the DomainRecord the registry's RDAP server serves. RDAP returns the
// registration as structured JSON, so the record and its contacts are read
// without the per-registrar free-text parsing the WHOIS plugin relies on.
type domain struct {
	name   string
	plugin *rdapPlugin
}

func (d *domain) Name() string {
	return d.name
}

func (d *domain) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return nil
	}

	// Only a domain registered with a registry (an apex) has a domain record;
	// a name below one, or under a hosting provider's suffix
	// (site.github.io), does not. The WHOIS plugin applies the same gate.
	name := strings.ToLower(fqdn.Name)
	if amassdns.RegistrableDomain(name) != name {
		return nil
	}

	return d.plugin.checkRegistration(e, d.name, oam.DomainRecord, dbt.ContentFilters{"domain": name},
		func() (*dbt.Entity, any) { return d.query(e, name, e.Entity) })
}

func (d *domain) query(e *et.Event, name string, asset *dbt.Entity) (*dbt.Entity, any) {
	_ = support.WaitLimit(e.Session.Ctx(), d.plugin.rlimit)

	record, err := d.plugin.client.QueryDomain(name)
	if err != nil || record == nil {
		return nil, nil
	}
	return d.store(e, record, asset), record
}

// store builds the DomainRecord from the RDAP response and links the domain
// name to it. The domain's registration dates come from the response's
// events, its DNSSEC flag from the secure-DNS object, and its WHOIS server
// from the port-43 referral.
func (d *domain) store(e *et.Event, resp *rdap.Domain, asset *dbt.Entity) *dbt.Entity {
	fqdn, ok := asset.Asset.(*oamdns.FQDN)
	if !ok {
		return nil
	}

	name := strings.ToLower(fqdn.Name)
	dr := &oamreg.DomainRecord{
		ID:          resp.Handle,
		Domain:      name,
		WhoisServer: strings.ToLower(resp.Port43),
		Status:      resp.Status,
		DNSSEC:      secureDNSSigned(resp.SecureDNS),
	}
	if ldh := strings.ToLower(resp.LDHName); ldh != "" && ldh != name {
		dr.Punycode = ldh
	}
	if resp.UnicodeName != "" {
		dr.Name = resp.UnicodeName
	}
	if _, ext, found := strings.Cut(name, "."); found {
		dr.Extension = ext
	}

	dates := eventDates(resp.Events)
	dr.CreatedDate = dates.created
	dr.UpdatedDate = cmp.Or(dates.changed, dates.rdapUpdated)
	dr.ExpirationDate = dates.expiration

	// A record with neither an identifier nor a registration date carries no
	// more than the name already known, so it is not stored.
	if dr.ID == "" && dr.CreatedDate == "" && len(dr.Status) == 0 {
		return nil
	}

	return d.plugin.storeRecord(e, asset, dr)
}

// secureDNSSigned reports whether the RDAP secure-DNS object says the zone is
// DNSSEC-signed: the delegation-signed flag when the server sets it, and
// otherwise the presence of a DS or key record.
func secureDNSSigned(s *rdap.SecureDNS) bool {
	if s == nil {
		return false
	}
	if s.DelegationSigned != nil {
		return *s.DelegationSigned
	}
	return len(s.DS) > 0 || len(s.Keys) > 0
}
