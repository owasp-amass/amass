// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package codehost

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/account"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

func targets(t *testing.T, sess *plugintest.Session, from *dbt.Entity, label string) []*dbt.Entity {
	t.Helper()

	ctx := context.Background()
	edges, err := sess.DB().OutgoingEdges(ctx, from, time.Time{}, label)
	if err != nil {
		return nil
	}
	var out []*dbt.Entity
	for _, edge := range edges {
		if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func newTestPlugin(t *testing.T) (*codeHosts, *plugintest.Session) {
	t.Helper()
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	c := NewCodeHosts().(*codeHosts)
	c.rlimit = rate.NewLimiter(rate.Inf, 1)
	c.budget = func() bool { return true }
	c.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	return c, sess
}

// A GitHub organization guessed from the domain is kept when its profile's
// website is in the footprint, with its repositories and public members.
func TestGuessedOrganizationInTheFootprint(t *testing.T) {
	c, sess := newTestPlugin(t)
	sess.Scope().AddDomain("example.com")
	web := sess.Web()
	web.Reply("GET api.github.com/orgs/example", http.StatusOK, `{"login":"example","type":"Organization",`+
		`"name":"Example Project","blog":"www.example.com","email":"info@example.com","is_verified":true}`)
	web.Reply("GET api.github.com/orgs/example/repos", http.StatusOK, `[
		{"html_url":"https://github.com/example/site","homepage":"https://docs.example.com","fork":false},
		{"html_url":"https://github.com/example/fork","homepage":"","fork":true}]`)
	web.Reply("GET api.github.com/orgs/example/public_members", http.StatusOK, `[{"login":"dev1"},{"login":"dev2"}]`)

	apex := sess.Asset(t, &oamdns.FQDN{Name: "example.com"})
	if err := c.check(&et.Event{Entity: apex, Session: sess, Dispatcher: &plugintest.Dispatcher{}}); err != nil {
		t.Fatal(err)
	}

	accts, err := sess.DB().FindEntitiesByContent(context.Background(), oam.Account, time.Time{}, 1,
		dbt.ContentFilters{"unique_id": "github:example"})
	if err != nil || len(accts) != 1 {
		t.Fatalf("the organization account = %v, %v; requests %v", accts, err, web.Requests())
	}
	acct := accts[0]
	if a := acct.Asset.(*account.Account); a.Type != account.CodeHostOrganization {
		t.Errorf("account = %+v", a)
	}
	if got := targets(t, sess, acct, "repository"); len(got) != 1 {
		t.Errorf("repositories = %v", got)
	}
	if got := targets(t, sess, acct, "website"); len(got) != 2 {
		t.Errorf("websites = %v", got)
	}
	if got := targets(t, sess, acct, "member"); len(got) != 2 {
		t.Errorf("members = %v", got)
	}
	doms := targets(t, sess, acct, "namespace_domain")
	if len(doms) != 1 || doms[0].Asset.(*oamdns.FQDN).Name != "example.com" {
		t.Errorf("namespace domain = %v", doms)
	}
	if crs := targets(t, sess, acct, "contact"); len(crs) != 1 || len(targets(t, sess, crs[0], "organization")) != 1 {
		t.Errorf("the profile's contact record = %v", crs)
	}
}

// A guessed organization whose profile names nothing in the footprint is
// someone else's, and nothing is stored or read past its profile.
func TestGuessedOrganizationElsewhere(t *testing.T) {
	c, sess := newTestPlugin(t)
	sess.Scope().AddDomain("example.com")
	web := sess.Web()
	web.Reply("GET api.github.com/orgs/example", http.StatusOK, `{"login":"example","type":"Organization",`+
		`"blog":"https://example.net","email":""}`)

	apex := sess.Asset(t, &oamdns.FQDN{Name: "example.com"})
	if err := c.check(&et.Event{Entity: apex, Session: sess, Dispatcher: &plugintest.Dispatcher{}}); err != nil {
		t.Fatal(err)
	}
	accts, _ := sess.DB().FindEntitiesByType(context.Background(), oam.Account, time.Time{}, 10)
	if len(accts) != 0 {
		t.Errorf("accounts = %v", accts)
	}
	if reqs := web.Requests(); len(reqs) != 1 {
		t.Errorf("requests = %v", reqs)
	}
}

func TestParseGitLab(t *testing.T) {
	p, id, ok := parseGitLabGroup([]byte(`{"id":42,"name":"Example","full_path":"example",` +
		`"web_url":"https://gitlab.com/groups/example"}`))
	if !ok || id != 42 || p.handle != "example" || p.page != "https://gitlab.com/groups/example" {
		t.Fatalf("parseGitLabGroup = %+v, %d, %v", p, id, ok)
	}
	repos := parseGitLabProjects([]byte(`[{"web_url":"https://gitlab.com/example/a","forked_from_project":null},
		{"web_url":"https://gitlab.com/example/b","forked_from_project":{"id":1}}]`), 10)
	if len(repos) != 1 || repos[0].page != "https://gitlab.com/example/a" {
		t.Errorf("parseGitLabProjects = %v", repos)
	}
}

func TestWebURL(t *testing.T) {
	for raw, want := range map[string]string{"www.example.com": "https://www.example.com",
		"http://example.com/x": "http://example.com/x", "": "", "ftp://example.com": ""} {
		got := ""
		if u := webURL(raw); u != nil {
			got = u.Raw
		}
		if got != want {
			t.Errorf("webURL(%q) = %q, want %q", raw, got, want)
		}
	}
}
