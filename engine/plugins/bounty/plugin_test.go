// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package bounty

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	"github.com/owasp-amass/open-asset-model/account"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

func platform(t *testing.T, key string) semantics.BountyPlatform {
	t.Helper()
	p, ok := semantics.BountyPlatformByKey(key)
	if !ok {
		t.Fatalf("platform %s missing", key)
	}
	return p
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in, host, prefix string
		ok               bool
	}{
		{"*.example.com", "example.com", "", true},
		{"https://api.example.com/v1/users", "api.example.com", "", true},
		{"www.example.co.uk:8443", "www.example.co.uk", "", true},
		{"Example.COM (production only)", "example.com", "", true},
		{"192.0.2.0/24", "", "192.0.2.0/24", true},
		{"198.51.100.7", "", "198.51.100.7/32", true},
		{"10.0.0.0/8", "", "", false},
		{"api.*.example.com", "", "", false},
		{"com.example.android", "", "", false},
		{"Acme iOS App", "", "", false},
		{"https://github.com/acme/widgets", "github.com", "", true},
		{"", "", "", false},
	}
	for _, c := range cases {
		host, pf, ok := parseTarget(c.in)
		if ok != c.ok || host != c.host || (c.prefix != "" && pf.String() != c.prefix) || (c.prefix == "" && pf.IsValid()) {
			t.Errorf("parseTarget(%q) = %q, %v, %v; want %q, %q, %v", c.in, host, pf, ok, c.host, c.prefix, c.ok)
		}
	}
}

const hackeroneFeed = `[
 {"name": "Acme Corp", "handle": "acme", "url": "https://hackerone.com/acme", "website": "https://www.acme.com",
  "targets": {"in_scope": [
   {"asset_identifier": "*.acme.com", "asset_type": "WILDCARD"},
   {"asset_identifier": "acme-cloud.io", "asset_type": "URL"},
   {"asset_identifier": "203.0.113.0/24", "asset_type": "CIDR"},
   {"asset_identifier": "com.acme.app", "asset_type": "GOOGLE_PLAY_APP_ID"},
   {"asset_identifier": "hackerone.com/acme", "asset_type": "OTHER"}],
   "out_of_scope": [{"asset_identifier": "acme.zendesk.com", "asset_type": "URL"}]}},
 {"name": "No Scope", "handle": "empty", "targets": {"in_scope": []}}
]`

const intigritiFeed = `[
 {"id": "x1", "name": "Widget NV", "company_handle": "widget", "handle": "widgetbe",
  "targets": {"in_scope": [{"type": "url", "endpoint": "https://portal.widget.be"}]}}
]`

const yeswehackFeed = `[
 {"id": 42, "slug": "gizmo-vdp", "name": "Gizmo", "disabled": false,
  "targets": {"in_scope": [{"target": "*.gizmo.fr", "type": "web-application"}]}},
 {"id": 43, "slug": "gone", "name": "Gone", "disabled": true,
  "targets": {"in_scope": [{"target": "*.gone.fr", "type": "web-application"}]}}
]`

func TestParseFeed(t *testing.T) {
	d := newDataset()
	for key, feed := range map[string]string{
		"hackerone": hackeroneFeed, "intigriti": intigritiFeed, "yeswehack": yeswehackFeed,
	} {
		if err := parseFeed(platform(t, key), strings.NewReader(feed), d); err != nil {
			t.Fatal(err)
		}
	}
	if len(d.programs) != 3 {
		t.Fatalf("want 3 programs (no empty or disabled ones), got %d", len(d.programs))
	}

	acme := d.lookup("acme.com")
	if len(acme) != 1 {
		t.Fatalf("acme.com programs = %d", len(acme))
	}
	p := acme[0]
	if p.id() != "hackerone:acme" || p.name != "Acme Corp" || p.website != "https://www.acme.com" ||
		p.page != "https://hackerone.com/acme" {
		t.Errorf("program = %+v", p)
	}
	slices.Sort(p.hosts)
	if !slices.Equal(p.hosts, []string{"acme-cloud.io", "acme.com"}) {
		t.Errorf("hosts = %v (the platform's own page and out-of-scope entries must be skipped)", p.hosts)
	}
	if len(p.prefixes) != 1 || p.prefixes[0] != netip.MustParsePrefix("203.0.113.0/24") {
		t.Errorf("prefixes = %v", p.prefixes)
	}
	if len(d.lookup("acme-cloud.io")) != 1 || len(d.lookup("zendesk.com")) != 0 {
		t.Error("index by registered domain is wrong")
	}

	if w := d.lookup("widget.be"); len(w) != 1 || w[0].id() != "intigriti:widget/widgetbe" ||
		w[0].page != "https://app.intigriti.com/programs/widget/widgetbe/detail" {
		t.Errorf("intigriti program = %+v", w)
	}
	if g := d.lookup("gizmo.fr"); len(g) != 1 || g[0].id() != "yeswehack:gizmo-vdp" {
		t.Errorf("yeswehack program = %+v", g)
	}
}

func TestStore(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.Scope().AddDomain("acme.com")
	b := NewBountyScopes().(*bountyScopes)
	apex := sess.Asset(t, &oamdns.FQDN{Name: "acme.com"})
	disp := &plugintest.Dispatcher{}
	e := &et.Event{Session: sess, Entity: apex, Dispatcher: disp}

	d := newDataset()
	if err := parseFeed(platform(t, "hackerone"), strings.NewReader(hackeroneFeed), d); err != nil {
		t.Fatal(err)
	}
	acct := b.store(e, "acme.com", d.lookup("acme.com")[0])
	if acct == nil {
		t.Fatal("the program was not stored")
	}
	a, ok := acct.Asset.(*account.Account)
	if !ok || a.ID != "hackerone:acme" || a.Type != account.BugBountyProgram || a.Username != "acme" {
		t.Fatalf("account = %+v", acct.Asset)
	}

	ctx := context.Background()
	scope, err := sess.DB().OutgoingEdges(ctx, acct, time.Time{}, "in_scope")
	if err != nil || len(scope) != 3 {
		t.Fatalf("in_scope edges: %d, %v", len(scope), err)
	}
	if pages, err := sess.DB().OutgoingEdges(ctx, acct, time.Time{}, "program_page"); err != nil || len(pages) != 1 {
		t.Errorf("program_page edges: %d, %v", len(pages), err)
	}

	tags, _ := sess.DB().FindEntityTags(ctx, acct, time.Time{})
	got := map[string]string{}
	for _, tag := range tags {
		if sp, ok := tag.Property.(*general.SimpleProperty); ok {
			got[sp.PropertyName] = sp.PropertyValue
		}
	}
	if got[PropProgramName] != "Acme Corp" || got[PropPlatform] != "HackerOne" {
		t.Errorf("account properties = %v", got)
	}

	// The website is the program's ContactRecord URL.
	crs, err := sess.DB().OutgoingEdges(ctx, acct, time.Time{}, "contact")
	if err != nil || len(crs) != 1 {
		t.Fatalf("contact edges: %d, %v", len(crs), err)
	}
	urls, err := sess.DB().OutgoingEdges(ctx, crs[0].ToEntity, time.Time{}, "url")
	if err != nil || len(urls) != 1 {
		t.Fatalf("contact url edges: %d, %v", len(urls), err)
	}
	site, err := sess.DB().FindEntityById(ctx, urls[0].ToEntity.ID)
	if err != nil {
		t.Fatal(err)
	}
	if u, ok := site.Asset.(*oamurl.URL); !ok || u.Raw != "https://www.acme.com" {
		t.Errorf("website = %+v", site.Asset)
	}

	// Only in-scope names other than the apex itself are dispatched.
	if names := disp.Names(); len(names) != 0 {
		t.Errorf("dispatched %v; acme-cloud.io is out of scope and acme.com is the event itself", names)
	}
}

// TestLiveFeeds downloads the real feeds and checks each still parses into
// programs. It needs network access, so it runs only with
// AMASS_LIVE_BOUNTY=1.
func TestLiveFeeds(t *testing.T) {
	if os.Getenv("AMASS_LIVE_BOUNTY") == "" {
		t.Skip("set AMASS_LIVE_BOUNTY=1 to check the live bug-bounty feeds")
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	for _, plat := range semantics.BountyPlatforms() {
		resp, err := client.Get(plat.Feed)
		if err != nil {
			t.Errorf("%s: %v", plat.Key, err)
			continue
		}
		d := newDataset()
		err = parseFeed(plat, resp.Body, d)
		_ = resp.Body.Close()
		if err != nil || len(d.programs) < 20 || len(d.byDomain) < 20 {
			t.Errorf("%s: %d programs, %d domains, %v", plat.Key, len(d.programs), len(d.byDomain), err)
			continue
		}
		t.Logf("%s: %d programs with domains or ranges, %d registered domains", plat.Key, len(d.programs), len(d.byDomain))
	}
}
