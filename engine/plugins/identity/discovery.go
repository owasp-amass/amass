// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"golang.org/x/net/publicsuffix"
)

// maxSigningCerts bounds the signing certificates kept from one federation
// metadata document (a key rollover lists two).
const maxSigningCerts = 4

// askedHosts counts, per session and registered domain, the names asked for
// their discovery document, and remembers the provider hosts already asked.
type askedHosts struct {
	mu        sync.Mutex
	counts    map[string]int
	providers map[string]bool
}

// take reports whether one more name of apex may be asked in the session
// (identity_providers.json max_hosts), and counts it.
func (a *askedHosts) take(session, apex string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.counts == nil {
		a.counts = make(map[string]int)
	}
	key := session + "|" + apex
	if a.counts[key] >= semantics.IdentityProviderCatalog().MaxHosts {
		return false
	}
	a.counts[key]++
	return true
}

// first reports whether provider host has not been asked in the session yet,
// and marks it asked.
func (a *askedHosts) first(session, host string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.providers == nil {
		a.providers = make(map[string]bool)
	}
	key := session + "|" + host
	if a.providers[key] {
		return false
	}
	a.providers[key] = true
	return true
}

// discover asks host for its OpenID Connect discovery document and records
// the issuer's host as the host the domain's users sign in at.
func (p *identity) discover(e *et.Event, host string) {
	body := p.get(e, "https://"+host+semantics.IdentityProviderCatalog().OIDCPath)
	if issuer := issuerHost(body); issuer != "" && issuer != host {
		p.signsInAt(e, e.Entity, issuer)
	}
}

// signsInAt records idp as the host from's users sign in at, then reads what
// the host says about its identity system: a provider tenant's organization
// identifier, or the signing certificates of the organization's own
// federation server. Each provider host is read once per session.
func (p *identity) signsInAt(e *et.Event, from *dbt.Entity, idp string) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	ent := support.LinkAsset(ctx, e.Session, from, "identity_provider", &oamdns.FQDN{Name: idp}, p.source)
	cancel()
	if ent == nil || !p.asked.first(e.Session.ID().String(), idp) {
		return
	}

	prov, hosted := semantics.IdentityProviderFor(idp)
	e.Session.Log().Info("identity provider found", "from", from.Asset.Key(), "host", idp,
		"provider", prov.Name, slog.Group("plugin", "name", p.name, "handler", p.name+"-Handler"))
	switch {
	case hosted && prov.TenantPath != "":
		p.tenantOf(e, from, prov, idp)
	case !hosted:
		p.signingCerts(e, ent, idp)
	}
}

// tenantOf asks a provider's tenant host for its organization identifier
// and records it as the identity tenant of from's registered domain.
func (p *identity) tenantOf(e *et.Event, from *dbt.Entity, prov semantics.IdentityProvider, idp string) {
	var meta struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(p.get(e, "https://"+idp+prov.TenantPath)), &meta); err != nil || meta.ID == "" {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()
	domain := from
	if fqdn, ok := from.Asset.(*oamdns.FQDN); ok {
		if apex, err := publicsuffix.EffectiveTLDPlusOne(fqdn.Name); err == nil && apex != fqdn.Name {
			if domain, err = e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: apex}); err != nil {
				return
			}
		}
	}
	_ = support.LinkAsset(ctx, e.Session, domain, "identity_tenant", &oamgen.Identifier{
		UniqueID: prov.TenantType + ":" + meta.ID, ID: meta.ID, Type: prov.TenantType,
	}, p.source)
}

// signingCerts reads the federation metadata of the organization's own
// sign-in host and records each certificate it names for signing tokens.
func (p *identity) signingCerts(e *et.Event, idpEnt *dbt.Entity, idp string) {
	body := p.get(e, "https://"+idp+semantics.IdentityProviderCatalog().FederationMetadataPath)
	certs := metadataSigningCerts(body)
	if len(certs) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()
	for _, c := range certs {
		_ = support.LinkAsset(ctx, e.Session, idpEnt, "signing_certificate", support.X509ToOAMTLSCertificate(c),
			p.source)
	}
}

// get returns the body of a successful GET of u, or "".
func (p *identity) get(e *et.Event, u string) string {
	_ = support.WaitLimit(e.Session.Ctx(), p.rlimit)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: u})
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	return resp.Body
}

// issuerHost returns the host of a discovery document's issuer, or "".
func issuerHost(body string) string {
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if body == "" || json.Unmarshal([]byte(body), &doc) != nil {
		return ""
	}
	return urlHost(doc.Issuer)
}

// urlHost returns the lower-cased host of an https URL, or "".
func urlHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(u.Scheme, "https") {
		return ""
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if !strings.Contains(host, ".") {
		return ""
	}
	return host
}

var (
	keyDescriptor = regexp.MustCompile(`(?is)<(?:\w+:)?KeyDescriptor\b([^>]*)>(.*?)</(?:\w+:)?KeyDescriptor>`)
	x509Element   = regexp.MustCompile(`(?is)<(?:\w+:)?X509Certificate>\s*([A-Za-z0-9+/=\s]+?)\s*</(?:\w+:)?X509Certificate>`)
	useEncryption = regexp.MustCompile(`(?i)\buse\s*=\s*["']encryption["']`)
)

// metadataSigningCerts returns the certificates a SAML or WS-Federation
// metadata document names for signing: those of key descriptors marked
// use="signing" or with no use (both), each once, at most maxSigningCerts.
func metadataSigningCerts(body string) []*x509.Certificate {
	seen := make(map[string]bool)
	var out []*x509.Certificate
	for _, kd := range keyDescriptor.FindAllStringSubmatch(body, -1) {
		if useEncryption.MatchString(kd[1]) {
			continue
		}
		for _, m := range x509Element.FindAllStringSubmatch(kd[2], -1) {
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(m[1]), ""))
			if err != nil || seen[string(der)] {
				continue
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				continue
			}
			seen[string(der)] = true
			if out = append(out, cert); len(out) == maxSigningCerts {
				return out
			}
		}
	}
	return out
}
