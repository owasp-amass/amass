// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/openrdap/rdap"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// recordDetail expands a registration record (an AutnumRecord, IPNetRecord or
// DomainRecord) into what its RDAP response carries: the RDAP URL, the WHOIS
// server and, for a domain, the name servers, and the registration contacts.
// A record from the TTL cache arrives without a response and is expanded from
// the edges RDAP already stored.
type recordDetail struct {
	name       string
	plugin     *rdapPlugin
	recType    oam.AssetType
	servers    []string // the FQDN edge labels
	contacts   []string // the ContactRecord edge labels (storeEntity)
	transforms []string
}

var recordDetailTransforms = []string{
	string(oam.FQDN),
	string(oam.URL),
	string(oam.ContactRecord),
	string(oam.Person),
	string(oam.Organization),
	string(oam.StreetAddress),
	string(oam.Identifier),
	string(oam.Phone),
}

// newRecordDetail returns the detail handler for a registration record type.
func newRecordDetail(rd *rdapPlugin, recType oam.AssetType) *recordDetail {
	r := &recordDetail{
		plugin:     rd,
		recType:    recType,
		servers:    []string{"whois_server"},
		contacts:   []string{"registrant", "admin_contact", "abuse_contact", "technical_contact"},
		transforms: recordDetailTransforms,
	}

	switch recType {
	case oam.AutnumRecord:
		r.name = rd.name + "-Autnum-Handler"
	case oam.IPNetRecord:
		r.name = rd.name + "-IPNetwork-Handler"
	case oam.DomainRecord:
		r.name = rd.name + "-Domain-Record-Handler"
		r.servers = []string{"name_server", "whois_server"}
		r.contacts = []string{"registrant_contact", "admin_contact", "technical_contact",
			"billing_contact", "registrar_contact"}
	}
	return r
}

func (r *recordDetail) Name() string {
	return r.name
}

func (r *recordDetail) check(e *et.Event) error {
	if e.Entity.Asset.AssetType() != r.recType {
		return errors.New("failed to cast the " + string(r.recType) + " asset")
	}

	matches, err := e.Session.Config().CheckTransformations(
		string(r.recType), append(r.transforms, r.plugin.name)...)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	if obj, ok := responseOf(e.Meta); ok {
		r.store(e, obj, e.Entity, matches)
	} else if findings := support.StoredFindings(e, e.Entity, recordName(e.Entity), r.plugin.name, matches,
		map[string][]string{
			string(oam.URL):           {"rdap_url"},
			string(oam.FQDN):          r.servers,
			string(oam.ContactRecord): r.contacts,
		}, r.plugin.source); len(findings) > 0 {
		support.ProcessAssetsWithSource(e, findings, r.plugin.source, r.plugin.name, r.name)
	}
	return nil
}

// response is what the detail handlers read from an RDAP object.
type response struct {
	links       []rdap.Link
	entities    []rdap.Entity
	nameservers []string
}

// responseOf returns the parts of the RDAP response attached to an event.
func responseOf(meta any) (*response, bool) {
	switch v := meta.(type) {
	case *rdap.Autnum:
		if v != nil {
			return &response{links: v.Links, entities: v.Entities}, true
		}
	case *rdap.IPNetwork:
		if v != nil {
			return &response{links: v.Links, entities: v.Entities}, true
		}
	case *rdap.Domain:
		if v != nil {
			resp := &response{links: v.Links, entities: v.Entities}
			for _, ns := range v.Nameservers {
				resp.nameservers = append(resp.nameservers, ns.LDHName)
			}
			return resp, true
		}
	}
	return nil, false
}

// whoisServer is the record's port-43 referral.
func whoisServer(record *dbt.Entity) string {
	switch v := record.Asset.(type) {
	case *oamreg.AutnumRecord:
		return v.WhoisServer
	case *oamreg.IPNetRecord:
		return v.WhoisServer
	case *oamreg.DomainRecord:
		return v.WhoisServer
	}
	return ""
}

func (r *recordDetail) store(e *et.Event, resp *response, record *dbt.Entity, m *config.Matches) {
	var findings []*support.Finding
	from := recordName(record)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if u := r.plugin.getJSONLink(resp.links); u != nil && m.IsMatch(string(oam.URL)) {
		if a, err := e.Session.DB().CreateAsset(ctx, u); err == nil && a != nil {
			findings = append(findings, &support.Finding{
				From: record, FromName: from, To: a, ToName: u.Raw,
				Rel: &general.SimpleRelation{Name: "rdap_url"},
			})
		}
	}

	if m.IsMatch(string(oam.FQDN)) {
		for _, ns := range resp.nameservers {
			findings = append(findings, fqdnFinding(ctx, e, record, from, ns, "name_server")...)
		}
		findings = append(findings, fqdnFinding(ctx, e, record, from, whoisServer(record), "whois_server")...)
	}

	// process the servers and the URL found above
	support.ProcessAssetsWithSource(e, findings, r.plugin.source, r.plugin.name, r.name)

	if m.IsMatch(string(oam.ContactRecord)) {
		for _, v := range resp.entities {
			r.plugin.storeEntity(e, 1, &v, record, r.plugin.source, m)
		}
	}
}

// fqdnFinding creates an in-scope FQDN and the finding for the edge from the
// record to it, or nothing when the name is empty or out of scope.
func fqdnFinding(ctx context.Context, e *et.Event, record *dbt.Entity, from, name, rel string) []*support.Finding {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return nil
	}

	fqdn := &oamdns.FQDN{Name: name}
	if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf <= 0 {
		return nil
	}

	a, err := e.Session.DB().CreateAsset(ctx, fqdn)
	if err != nil || a == nil {
		return nil
	}
	return []*support.Finding{{
		From: record, FromName: from, To: a, ToName: name,
		Rel: &general.SimpleRelation{Name: rel},
	}}
}
