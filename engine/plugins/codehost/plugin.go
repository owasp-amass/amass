// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package codehost reads an organization's public code-host organizations,
// from each in-scope registered domain: the GitHub and GitLab accounts its
// stored website and social-media profile URLs name, and the GitHub
// organization named for the domain when that organization's profile names
// a website or email in the footprint (semantics code_hosts.json). Each is
// stored as a code_host_organization Account with its profile, its public
// repositories, the websites they name and its public members.
package codehost

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/account"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"golang.org/x/time/rate"
)

// maxBody bounds a code host's answer.
const maxBody = 4 << 20

// githubBudget is the engine's shared hourly budget of GitHub requests.
var githubBudget = sync.OnceValue(func() *rate.Limiter {
	n := semantics.CodeHostCatalog().GitHub.RequestsPerHour
	return rate.NewLimiter(rate.Every(time.Hour/time.Duration(n)), n)
})

type codeHosts struct {
	name    string
	log     *slog.Logger
	source  *et.Source
	rlimit  *rate.Limiter // pacing of every request
	budget  func() bool   // whether a GitHub request may be made now
	catalog semantics.CodeHosts

	mu   sync.Mutex
	seen map[string]bool // session|host:handle already read
}

func NewCodeHosts() et.Plugin {
	return &codeHosts{
		name:    "Code-Hosts",
		source:  &et.Source{Name: "Code-Hosts", Confidence: 90},
		rlimit:  rate.NewLimiter(rate.Every(time.Second), 1),
		budget:  func() bool { return githubBudget().Allow() },
		catalog: semantics.CodeHostCatalog(),
		seen:    make(map[string]bool),
	}
}

func (c *codeHosts) Name() string { return c.name }

func (c *codeHosts) Start(r et.Registry) error {
	c.log = r.Log().WithGroup("plugin").With("name", c.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       c,
		Name:         c.name + "-Handler",
		Position:     42,
		MaxInstances: support.MinHandlerInstances,
		Transforms: []string{string(oam.Account), string(oam.URL), string(oam.ContactRecord),
			string(oam.Organization)},
		EventType: oam.FQDN,
		Callback:  c.check,
	}); err != nil {
		return err
	}

	c.log.Info("Plugin started")
	return nil
}

func (c *codeHosts) Stop() { c.log.Info("Plugin stopped") }

// candidate is a code-host account to read: named by the organization's
// stored URLs, or guessed from the domain.
type candidate struct {
	platform string // GitHub or GitLab
	handle   string
	named    bool
}

func (c *codeHosts) check(e *et.Event) error {
	apex, err := support.InScopeApexToCheck(e, oam.Account, c.source, c.name)
	if err != nil || apex == "" {
		return err
	}

	owner := org.OrgForControlledDomain(e.Session, apex)
	f := support.FootprintOf(e, apex)
	for _, cand := range candidates(e, owner, apex) {
		if !c.first(e, cand) {
			continue
		}
		switch cand.platform {
		case "GitHub":
			c.github(e, owner, apex, f, cand)
		case "GitLab":
			if cand.named {
				c.gitlab(e, owner, apex, cand)
			}
		}
	}
	return nil
}

// first reports whether the session has not read the candidate yet, and
// marks it read.
func (c *codeHosts) first(e *et.Event, cand candidate) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := e.Session.ID().String() + "|" + cand.platform + ":" + strings.ToLower(cand.handle)
	if c.seen[key] {
		return false
	}
	c.seen[key] = true
	return true
}

// candidates are the code-host accounts the owner's stored website and
// social-media profile URLs name, then the GitHub organization named for the
// domain's first label.
func candidates(e *et.Event, owner *dbt.Entity, apex string) []candidate {
	var out []candidate
	has := map[string]bool{}
	add := func(cand candidate) {
		if key := cand.platform + ":" + strings.ToLower(cand.handle); !has[key] {
			has[key] = true
			out = append(out, cand)
		}
	}

	if owner != nil {
		ctx, cancel := context.WithTimeout(e.Session.Ctx(), 20*time.Second)
		defer cancel()
		edges, _ := e.Session.DB().OutgoingEdges(ctx, owner, time.Time{}, "website", "social_media_profile")
		for _, edge := range edges {
			ent, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID)
			if err != nil {
				continue
			}
			if u, ok := ent.Asset.(*oamurl.URL); ok {
				if p, handle, ok := semantics.AccountHandle(u.Raw); ok && (p.Platform == "GitHub" ||
					p.Platform == "GitLab") {
					add(candidate{platform: p.Platform, handle: handle, named: true})
				}
			}
		}
	}
	if label, _, ok := strings.Cut(apex, "."); ok && label != "" {
		add(candidate{platform: "GitHub", handle: label})
	}
	return out
}

// profile is what a code-host organization's profile says about it.
type profile struct {
	host, handle, page string
	name, website      string
	email              string
	verified           bool
}

// store records a code-host organization as an Account: its profile as a
// ContactRecord, the domain it is tied to, the organization that has it,
// its repositories and the websites they name (dispatched), and its members.
func (c *codeHosts) store(e *et.Event, owner *dbt.Entity, domain string, p profile, repos []repository,
	members []string) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 2*time.Minute)
	defer cancel()
	sess := e.Session
	db := sess.DB()

	acct, err := db.CreateAsset(ctx, &account.Account{ID: p.host + ":" + p.handle,
		Type: account.CodeHostOrganization, Username: p.handle})
	if err != nil || acct == nil {
		return
	}
	support.AddSource(ctx, sess, acct, c.source)
	if p.verified {
		support.AddProperty(ctx, sess, acct, "verified_domain", "true")
	}
	if owner != nil {
		support.Link(ctx, sess, owner, "account", acct, c.source)
	}
	if dom, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: domain}); err == nil && dom != nil {
		support.Link(ctx, sess, acct, "namespace_domain", dom, c.source)
	}

	if cr := support.LinkContactRecord(ctx, sess, acct, "contact", p.page, c.source); cr != nil {
		if p.website != "" {
			_ = support.LinkContactValue(ctx, sess, cr, p.website, c.source)
		}
		if p.email != "" {
			_ = support.LinkEmail(ctx, sess, cr, "id", p.email, c.source)
		}
		if p.name != "" {
			_ = org.LinkContactOrg(e, cr, p.name, c.source)
		}
	}

	c.link(ctx, e, acct, "website", p.website, true)
	for _, r := range repos {
		c.link(ctx, e, acct, "repository", r.page, false)
		c.link(ctx, e, acct, "website", r.homepage, true)
	}
	for _, m := range members {
		ent, err := db.CreateAsset(ctx, &account.Account{ID: p.host + ":" + m, Type: account.CodeHostUser,
			Username: m})
		if err != nil || ent == nil {
			continue
		}
		support.AddSource(ctx, sess, ent, c.source)
		support.Link(ctx, sess, acct, "member", ent, c.source)
	}
	sess.Log().Info("code-host organization found", "account", p.host+":"+p.handle, "domain", domain,
		"repositories", len(repos), "members", len(members), slog.Group("plugin", "name", c.name,
			"handler", c.name+"-Handler"))
}

// link stores raw as a URL the account names under label, and dispatches it
// when asked, so scope decides what is collected from it.
func (c *codeHosts) link(ctx context.Context, e *et.Event, acct *dbt.Entity, label, raw string, dispatch bool) {
	u := webURL(raw)
	if u == nil {
		return
	}
	ent, err := e.Session.DB().CreateAsset(ctx, u)
	if err != nil || ent == nil {
		return
	}
	support.AddSource(ctx, e.Session, ent, c.source)
	support.Link(ctx, e.Session, acct, label, ent, c.source)
	if dispatch {
		_ = e.Dispatcher.DispatchEvent(&et.Event{Name: u.Raw, Entity: ent, Session: e.Session})
	}
}

// webURL is the URL asset of a website a profile names, which often lacks
// its scheme ("owasp.org"), or nil.
func webURL(raw string) *oamurl.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") {
		return nil
	}
	return support.RawURLToOAM(raw)
}

// tie returns the footprint domain a profile's website or email is in, or
// "".
func tie(f support.Footprint, p profile) string {
	if u := webURL(p.website); u != nil {
		if d := f.Host(u.Raw); d != "" {
			return d
		}
	}
	return f.Address(p.email)
}
