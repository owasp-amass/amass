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
// It also finds the host the domain's users sign in at: a federated tenant's
// AuthURL, and the issuer of the OpenID Connect discovery document of the
// registered domain and of its sign-in names (discovery.go). A provider's
// tenant host gives the provider's organization identifier where it
// publishes one (Okta); the organization's own federation server gives the
// certificates that sign its tokens.
//
// The active pre-auth user-enumeration oracle is deliberately excluded — it
// is credential-attack preparation, not evidence collection.
package identity

import (
	"context"
	"html"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/amass/v5/internal/semantics"
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
	asked  askedHosts
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

	// The identity tenant and federation trust belong to the registered
	// domain, not to each subdomain, so Microsoft is asked once per apex; the
	// apex and its sign-in names are asked for their discovery document.
	host := strings.ToLower(fqdn.Name)
	apex, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || (apex != host && !semantics.IsLoginLabel(strings.SplitN(host, ".", 2)[0])) {
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

	if apex == host {
		p.microsoft(e, host)
	}
	if p.asked.take(e.Session.ID().String(), apex) {
		p.discover(e, host)
	}
	return nil
}

// microsoft resolves the domain's Entra tenant, its namespace, brand name
// and federation server, and the sibling domains of its tenant.
func (p *identity) microsoft(e *et.Event, host string) {
	tenant := p.entraTenant(e, e.Entity, host)
	r := p.userRealm(e, host)
	if r.namespace != "" {
		owner := e.Entity
		if tenant != nil {
			owner = tenant
		}
		ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
		support.AddProperty(ctx, e.Session, owner, "namespace_type", r.namespace)
		if r.brand != "" {
			support.AddProperty(ctx, e.Session, owner, "federation_brand_name", r.brand)
		}
		cancel()
	}
	if r.authHost != "" {
		p.signsInAt(e, e.Entity, r.authHost)
	}

	// A confirmed Microsoft tenant (either probe) means GetFederationInformation
	// will answer; skip it on non-Microsoft domains to avoid pointless calls.
	if tenant != nil || r.namespace != "" {
		p.federation(e, e.Entity, host)
	}
}

var guidInIssuer = regexp.MustCompile(`(?i)"issuer"\s*:\s*"[^"]*?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`)

// entraTenant fetches the domain's Entra OIDC metadata and, when the issuer
// carries a tenant GUID, records it as an Identifier the domain's identity
// tenant points at. Returns the Identifier entity, or nil.
func (p *identity) entraTenant(e *et.Event, apex *dbt.Entity, host string) *dbt.Entity {
	guid := tenantID(p.get(e, "https://login.microsoftonline.com/"+host+"/.well-known/openid-configuration"))
	if guid == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()
	ident := support.LinkAsset(ctx, e.Session, apex, "identity_tenant", &oamgen.Identifier{
		UniqueID: oamgen.AzureTenantID + ":" + guid, ID: guid, Type: oamgen.AzureTenantID,
	}, p.source)
	if ident == nil {
		return nil
	}
	e.Session.Log().Info("Entra tenant resolved", "domain", host, "tenant", guid,
		slog.Group("plugin", "name", p.name, "handler", p.name+"-Handler"))
	return ident
}

// tenantID returns the Entra tenant GUID in the issuer of an OpenID
// configuration document, lower-cased, or "".
func tenantID(body string) string {
	if m := guidInIssuer.FindStringSubmatch(body); len(m) == 2 {
		return strings.ToLower(m[1])
	}
	return ""
}

var (
	nameSpaceType = regexp.MustCompile(`(?i)<NameSpaceType>\s*([A-Za-z]+)\s*</NameSpaceType>`)
	brandName     = regexp.MustCompile(`(?i)<FederationBrandName>\s*([^<]*?)\s*</FederationBrandName>`)
	authURL       = regexp.MustCompile(`(?i)<AuthURL>\s*([^<]*?)\s*</AuthURL>`)
)

// realm is what Microsoft's getuserrealm.srf says about a domain.
type realm struct {
	namespace string // "managed" or "federated"
	brand     string // the tenant's federation brand name
	authHost  string // a federated tenant's sign-in host
}

// userRealm reads the Microsoft getuserrealm.srf answer for the domain: its
// namespace, "managed" (auth terminates at Entra) or "federated" (routes to
// an upstream IdP), and for a federated tenant its brand name and sign-in
// host. A synthetic admin@ probe user is used; the probe hits Microsoft,
// never the target.
func (p *identity) userRealm(e *et.Event, host string) realm {
	return parseRealm(p.get(e, "https://login.microsoftonline.com/getuserrealm.srf?login=admin@"+host+"&xml=1"))
}

// parseRealm reads a getuserrealm.srf answer. The brand name and sign-in host
// are kept only for a known namespace.
func parseRealm(body string) realm {
	r := realm{namespace: namespaceType(body)}
	if r.namespace == "" {
		return realm{}
	}
	if m := brandName.FindStringSubmatch(body); len(m) == 2 {
		r.brand = html.UnescapeString(m[1])
	}
	if m := authURL.FindStringSubmatch(body); len(m) == 2 {
		r.authHost = urlHost(html.UnescapeString(m[1]))
	}
	return r
}

// namespaceType returns the NameSpaceType of a getuserrealm.srf answer,
// "managed" or "federated", or "" for Unknown or none.
func namespaceType(body string) string {
	m := nameSpaceType.FindStringSubmatch(body)
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

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL:    "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc",
		Method: http.MethodPost,
		Header: amasshttp.Header{
			"Content-Type": []string{"text/xml; charset=utf-8"},
			"SOAPAction":   []string{`"` + fedInfoAction + `"`},
			"User-Agent":   []string{"AutodiscoverClient"},
		},
		Body: federationRequest(host),
	})
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return
	}

	var n int
	for _, sib := range federationSiblings(resp.Body, host) {
		if support.LinkAsset(ctx, e.Session, apex, "federated_with", &oamdns.FQDN{Name: sib}, p.source) != nil {
			n++
		}
	}
	if n > 0 {
		e.Session.Log().Info("tenant federation mapped", "domain", host, "siblings", n,
			slog.Group("plugin", "name", p.name, "handler", p.name+"-Handler"))
	}
}

// federationRequest returns the GetFederationInformation SOAP request for a
// domain.
func federationRequest(host string) string {
	return `<?xml version="1.0" encoding="utf-8"?>` +
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
}

// federationSiblings returns the domains a GetFederationInformation answer
// lists as sharing the tenant, lower-cased and each once, without the domain
// itself, its subdomains or Microsoft's *.onmicrosoft.com routing names.
func federationSiblings(body, host string) []string {
	seen := map[string]bool{host: true}
	var out []string
	for _, m := range siblingDomain.FindAllStringSubmatch(body, -1) {
		sib := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(m[1])), ".")
		if sib == "" || seen[sib] || !strings.Contains(sib, ".") {
			continue
		}
		seen[sib] = true
		// a *.onmicrosoft.com name is the tenant's routing label, not a sibling
		if strings.HasSuffix(sib, "."+host) || strings.HasSuffix(sib, ".onmicrosoft.com") {
			continue
		}
		out = append(out, sib)
	}
	return out
}
