// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package packages collects the software packages an organization publishes
// on public package registries, from each in-scope registered domain: the
// Maven Central groups named for the domain, and the npm packages its email
// addresses maintain or whose homepage it hosts (semantics
// package_registries.json). Each package is stored as a Product named by its
// Package URL, and its registry namespace as an Account joined to the domain
// it is tied to; the websites the packages name are stored and handed to the
// engine, where scope decides what is collected from them.
package packages

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/account"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/platform"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"golang.org/x/time/rate"
)

// Properties this plugin stores.
const (
	// PropURLRole on a Product's website relation says which URL a package
	// named: its homepage, its project page, its source repository, or its
	// publisher's organization page.
	PropURLRole = "url_role"
)

// URL roles.
const (
	RoleHomepage     = "homepage"
	RoleProject      = "project"
	RoleRepository   = "repository"
	RoleOrganization = "organization"
)

// maxPackageBody bounds a registry answer or a POM.
const maxPackageBody = 2 << 20

type packagesPlugin struct {
	name    string
	log     *slog.Logger
	source  *et.Source
	rlimit  *rate.Limiter
	catalog semantics.PackageRegistries
}

func NewPackages() et.Plugin {
	return &packagesPlugin{
		name:   "Package-Registries",
		source: &et.Source{Name: "Package-Registries", Confidence: 90},
		rlimit: rate.NewLimiter(rate.Every(time.Second), 1),
	}
}

func (p *packagesPlugin) Name() string { return p.name }

func (p *packagesPlugin) Start(r et.Registry) error {
	p.log = r.Log().WithGroup("plugin").With("name", p.name)
	p.catalog = semantics.PackageRegistryCatalog()

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       p,
		Name:         p.name + "-Handler",
		Position:     41,
		MaxInstances: support.MinHandlerInstances,
		Transforms: []string{string(oam.Account), string(oam.Product), string(oam.Identifier), string(oam.URL),
			string(oam.Organization)},
		EventType: oam.FQDN,
		Callback:  p.check,
	}); err != nil {
		return err
	}

	p.log.Info("Plugin started")
	return nil
}

func (p *packagesPlugin) Stop() { p.log.Info("Plugin stopped") }

// pkg is one published package as a registry describes it.
type pkg struct {
	registry  string // maven or npm
	namespace string // groupId, @scope or ~user
	name      string // artifactId or package name
	title     string // the name the registry shows: group:artifact, or the npm package name
	purl      string
	version   string // the newest version, whose POM is read (Maven)
	updated   int64  // milliseconds since the epoch, for ordering
	urls      []pkgURL
	// organization is the publisher a Maven POM names
	organization string
	// maintainers are the maintainers' addresses at the domain (npm)
	maintainers []string
	// nameTied is set when the namespace is named for the domain (a Maven
	// groupId); an npm namespace is tied to it by its maintainers' addresses
	nameTied bool
}

// namespacePage returns the registry's page for the package's namespace, the
// locator of what the registry publishes about the namespace.
func (k pkg) namespacePage() string {
	switch k.registry {
	case "npm":
		if scope, ok := strings.CutPrefix(k.namespace, "@"); ok {
			return "https://www.npmjs.com/org/" + scope
		}
		return "https://www.npmjs.com/" + k.namespace
	case "maven":
		return "https://central.sonatype.com/namespace/" + k.namespace
	}
	return ""
}

type pkgURL struct {
	raw, role string
}

func (p *packagesPlugin) check(e *et.Event) error {
	apex, err := support.InScopeApexToCheck(e, oam.Product, p.source, p.name)
	if err != nil || apex == "" {
		return err
	}

	pkgs := p.maven(e, apex)
	pkgs = append(pkgs, p.npm(e, apex)...)
	for _, k := range pkgs {
		p.store(e, apex, k)
	}
	return nil
}

// store records a package as a Product, its namespace as an Account, and the
// URLs it names, and hands the URLs to the engine.
func (p *packagesPlugin) store(e *et.Event, apex string, k pkg) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Minute)
	defer cancel()
	sess := e.Session
	db := sess.DB()

	acct, err := db.CreateAsset(ctx, &account.Account{ID: k.registry + ":" + k.namespace,
		Type: account.PackageNamespace, Username: k.namespace})
	if err != nil || acct == nil {
		return
	}
	support.AddSource(ctx, sess, acct, p.source)
	if k.nameTied || len(k.maintainers) > 0 {
		if dom, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: apex}); err == nil && dom != nil {
			support.Link(ctx, sess, acct, "namespace_domain", dom, p.source)
		}
	}
	// The maintainers' addresses at the domain, the reason an npm package was
	// kept, as the namespace's ContactRecord (Account --contact-->
	// ContactRecord --id--> Identifier).
	if len(k.maintainers) > 0 {
		if cr := support.LinkContactRecord(ctx, sess, acct, "contact", k.namespacePage(), p.source); cr != nil {
			for _, m := range k.maintainers {
				support.LinkEmail(ctx, sess, cr, "id", m, p.source)
			}
		}
	}

	prod, err := db.CreateAsset(ctx, &platform.Product{ID: k.purl, Name: k.title,
		Type: p.catalog.ProductType, Category: k.registry})
	if err != nil || prod == nil {
		return
	}
	support.AddSource(ctx, sess, prod, p.source)
	support.Link(ctx, sess, acct, "package", prod, p.source)
	if id, err := db.CreateAsset(ctx, &general.Identifier{UniqueID: general.PackageURL + ":" + k.purl,
		ID: k.purl, Type: general.PackageURL}); err == nil && id != nil {
		support.AddSource(ctx, sess, id, p.source)
		support.Link(ctx, sess, prod, "id", id, p.source)
	}

	if k.organization != "" {
		_, _ = org.CreateOrgAsset(sess, prod, &general.SimpleRelation{Name: "manufacturer"},
			&oamorg.Organization{Name: k.organization}, p.source)
	}

	for _, u := range k.urls {
		ou := packageURL(u.raw)
		if ou == nil {
			continue
		}
		ent, err := db.CreateAsset(ctx, ou)
		if err != nil || ent == nil {
			continue
		}
		support.AddSource(ctx, sess, ent, p.source)
		edge := support.Link(ctx, sess, prod, "website", ent, p.source)
		if edge == nil {
			continue
		}
		support.AddEdgeProperty(ctx, sess, edge, PropURLRole, u.role)
		_ = e.Dispatcher.DispatchEvent(&et.Event{Name: ou.Raw, Entity: ent, Session: sess})
	}
	sess.Log().Info(fmt.Sprintf("package %s found for %s", k.purl, apex),
		slog.Group("plugin", "name", p.name, "handler", p.name+"-Handler"))
}

// packageURL returns the URL asset for a URL a package names, or nil when it
// is not an http(s) URL. URLs on code hosts and registry sites are kept: the
// controlled-footprint walk does not pass control from them to the shared
// host (lens.SharedPlatformHost).
func packageURL(raw string) *oamurl.URL {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "git+"))
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil
	}
	u.Fragment = ""
	return support.RawURLToOAM(u.String())
}

// ownAddress reports whether an email address is at the domain or one of its
// subdomains.
func ownAddress(email, apex string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndexByte(email, '@')
	if at < 1 {
		return false
	}
	host := email[at+1:]
	return host == apex || strings.HasSuffix(host, "."+apex)
}

// ownHost reports whether a URL's host is the domain or under it.
func ownHost(raw, apex string) bool {
	u, err := url.Parse(strings.TrimPrefix(strings.TrimSpace(raw), "git+"))
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == apex || strings.HasSuffix(host, "."+apex)
}

// newest orders packages newest first and keeps at most n.
func newest(pkgs []pkg, n int) []pkg {
	sort.SliceStable(pkgs, func(i, j int) bool { return pkgs[i].updated > pkgs[j].updated })
	if len(pkgs) > n {
		pkgs = pkgs[:n]
	}
	return pkgs
}
