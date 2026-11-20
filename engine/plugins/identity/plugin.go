// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package identity maps a registered domain's identity fabric from passive,
// provider-side probes — no packets to the target's own infrastructure. It
// resolves the Microsoft Entra (Azure AD) tenant behind a domain (the tenant
// GUID, and whether the namespace is Managed or Federated) and walks the
// tenant's federation boundary with GetFederationInformation to surface the
// sibling domains that share the same tenant trust. Siblings are recorded as
// discover-only federated_with leads for the horizontal-correlation lens to
// weigh, never auto-enumerated.
//
// Scope: Microsoft (Entra/M365) only in this pass. Okta/ADFS/SAML/OIDC
// fingerprinting is a planned follow-on. The active pre-auth user-enumeration
// oracle is deliberately excluded — it is credential-attack preparation, not
// evidence collection.
package identity

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
)

type identity struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewIdentity() et.Plugin {
	return &identity{
		name:   "Identity",
		rlimit: rate.NewLimiter(rate.Every(2*time.Second), 1),
		source: &et.Source{Name: "Identity", Confidence: 100},
	}
}

func (p *identity) Name() string { return p.name }

func (p *identity) Start(r et.Registry) error {
	p.log = r.Log().WithGroup("plugin").With("name", p.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       p,
		Name:         p.name + "-Handler",
		Position:     41,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Identifier), string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     p.check,
	}); err != nil {
		return err
	}

	p.log.Info("Plugin started")
	return nil
}

func (p *identity) Stop() { p.log.Info("Plugin stopped") }

func (p *identity) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return nil
	}

	// The identity tenant and federation trust belong to the registered domain,
	// not to each subdomain, so this runs once per apex.
	host := strings.ToLower(fqdn.Name)
	if dom, err := publicsuffix.EffectiveTLDPlusOne(host); err != nil || dom != host {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.Identifier), p.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, p.source, since) {
		return nil
	}
	support.MarkAssetMonitored(e.Session, e.Entity, p.source)

	tenant := p.entraTenant(e, e.Entity, host)
	ns := p.userRealm(e, host)
	switch {
	case tenant != nil && ns != "":
		p.property(e, tenant, "namespace_type", ns)
	case ns != "":
		p.property(e, e.Entity, "namespace_type", ns)
	}

	// A confirmed Microsoft tenant (either probe) means GetFederationInformation
	// will answer; skip it on non-Microsoft domains to avoid pointless calls.
	if tenant != nil || ns != "" {
		p.federation(e, e.Entity, host)
	}
	return nil
}

var guidInIssuer = regexp.MustCompile(`(?i)"issuer"\s*:\s*"[^"]*?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`)

// entraTenant fetches the domain's Entra OIDC metadata and, when the issuer
// carries a tenant GUID, records it as an Identifier the domain's identity
// tenant points at. Returns the Identifier entity, or nil.
func (p *identity) entraTenant(e *et.Event, apex *dbt.Entity, host string) *dbt.Entity {
	_ = support.WaitLimit(e.Session.Ctx(), p.rlimit)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()

	url := "https://login.microsoftonline.com/" + host + "/.well-known/openid-configuration"
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: url})
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return nil
	}

	m := guidInIssuer.FindStringSubmatch(resp.Body)
	if len(m) < 2 {
		return nil
	}
	guid := strings.ToLower(m[1])

	ident, err := e.Session.DB().CreateAsset(ctx, &oamgen.Identifier{
		UniqueID: fmt.Sprintf("%s:%s", oamgen.AzureTenantID, guid), ID: guid, Type: oamgen.AzureTenantID,
	})
	if err != nil || ident == nil {
		return nil
	}

	p.edge(ctx, e, apex, ident, "identity_tenant")
	e.Session.Log().Info("Entra tenant resolved", "domain", host, "tenant", guid,
		slog.Group("plugin", "name", p.name, "handler", p.name+"-Handler"))
	return ident
}

var nameSpaceType = regexp.MustCompile(`(?i)<NameSpaceType>\s*([A-Za-z]+)\s*</NameSpaceType>`)

// userRealm reads the Microsoft getuserrealm.srf namespace for the domain:
// "managed" (auth terminates at Entra) or "federated" (routes to an upstream
// IdP). Returns "" for Unknown or no answer. A synthetic admin@ probe user is
// used; the probe hits Microsoft, never the target.
func (p *identity) userRealm(e *et.Event, host string) string {
	_ = support.WaitLimit(e.Session.Ctx(), p.rlimit)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()

	url := "https://login.microsoftonline.com/getuserrealm.srf?login=admin@" + host + "&xml=1"
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: url})
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return ""
	}

	m := nameSpaceType.FindStringSubmatch(resp.Body)
	if len(m) < 2 {
		return ""
	}
	switch ns := strings.ToLower(m[1]); ns {
	case "managed", "federated":
		return ns
	default:
		return ""
	}
}

const fedInfoAction = "http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"

var siblingDomain = regexp.MustCompile(`(?i)<(?:\w+:)?Domain>\s*([^<\s][^<]*?)\s*</(?:\w+:)?Domain>`)

// federation posts GetFederationInformation to Microsoft and records every
// sibling domain that shares the domain's tenant as a discover-only
// federated_with lead. Siblings are not dispatched for enumeration; the
// horizontal-correlation lens weighs them for review.
func (p *identity) federation(e *et.Event, apex *dbt.Entity, host string) {
	_ = support.WaitLimit(e.Session.Ctx(), p.rlimit)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 20*time.Second)
	defer cancel()

	body := `<?xml version="1.0" encoding="utf-8"?>` +
		`<soap:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" ` +
		`xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`xmlns:autodiscover="http://schemas.microsoft.com/exchange/2010/Autodiscover">` +
		`<soap:Header>` +
		`<a:Action soap:mustUnderstand="1">` + fedInfoAction + `</a:Action>` +
		`<a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>` +
		`<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>` +
		`</soap:Header>` +
		`<soap:Body><autodiscover:GetFederationInformationRequestMessage><autodiscover:Request>` +
		`<autodiscover:Domain>` + host + `</autodiscover:Domain>` +
		`</autodiscover:Request></autodiscover:GetFederationInformationRequestMessage></soap:Body></soap:Envelope>`

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL:    "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc",
		Method: http.MethodPost,
		Header: amasshttp.Header{
			"Content-Type": []string{"text/xml; charset=utf-8"},
			"SOAPAction":   []string{`"` + fedInfoAction + `"`},
			"User-Agent":   []string{"AutodiscoverClient"},
		},
		Body: body,
	})
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return
	}

	seen := map[string]bool{host: true}
	var n int
	for _, m := range siblingDomain.FindAllStringSubmatch(resp.Body, -1) {
		sib := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(m[1])), ".")
		if sib == "" || seen[sib] || !strings.Contains(sib, ".") {
			continue
		}
		seen[sib] = true
		// Skip the seed's own subdomains and Microsoft's routing domains; a
		// *.onmicrosoft.com name is the tenant's routing label, not a sibling.
		if strings.HasSuffix(sib, "."+host) || strings.HasSuffix(sib, ".onmicrosoft.com") {
			continue
		}

		sibEnt, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: sib})
		if err != nil || sibEnt == nil {
			continue
		}
		p.edge(ctx, e, apex, sibEnt, "federated_with")
		n++
	}
	if n > 0 {
		e.Session.Log().Info("tenant federation mapped", "domain", host, "siblings", n,
			slog.Group("plugin", "name", p.name, "handler", p.name+"-Handler"))
	}
}

func (p *identity) edge(ctx context.Context, e *et.Event, from, to *dbt.Entity, label string) {
	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &oamgen.SimpleRelation{Name: label},
		FromEntity: from,
		ToEntity:   to,
	})
	if err != nil || edge == nil {
		return
	}
	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &oamgen.SourceProperty{
		Source:     p.source.Name,
		Confidence: p.source.Confidence,
	})
}

func (p *identity) property(e *et.Event, entity *dbt.Entity, name, value string) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()
	_, _ = e.Session.DB().CreateEntityProperty(ctx, entity,
		&oamgen.SimpleProperty{PropertyName: name, PropertyValue: value})
}
