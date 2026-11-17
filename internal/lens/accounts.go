// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// LensAccounts asks which platform accounts a domain or organization has —
// code hosts, social media and the like — computed from the profile URLs
// stored for it. The accounts are derived when asked, not written: the URL is
// the evidence (ai-design-principles.md, principle 10). Nothing is written and
// no page is fetched.
const LensAccounts = "accounts"

var accountPlatformsJSON = semantics.File("account_platforms.json")

var accountsLens = SubjectLens{
	Name:    LensAccounts,
	Command: "accounts",
	Description: "List the platform accounts (code hosts, social media and the like) a domain or organization " +
		"has, computed from the profile URLs stored for it. Read-only",
	Examples: []string{"What accounts does <organization> have?",
		"Is <organization> on GitHub, and under what handle?",
		"Which social-media accounts are tied to <domain>?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindAccounts(ctx, g, schema, root, opts.Limits)
	},
}

type accountPlatform struct {
	Platform       string   `json:"platform"`
	AccountType    string   `json:"account_type"`
	Hosts          []string `json:"hosts"`
	HandlePatterns []string `json:"handle_patterns"`
	Reserved       []string `json:"reserved"`
	Source         string   `json:"source"`
	res            []*regexp.Regexp
	reserved       map[string]bool
}

type accountRules struct {
	License   string            `json:"_license"`
	About     string            `json:"_about"`
	Platforms []accountPlatform `json:"platforms"`
}

var loadAccountRules = sync.OnceValue(func() accountRules {
	var r accountRules
	if err := graph.DecodeStrict(accountPlatformsJSON, &r); err != nil {
		panic("account_platforms.json: " + err.Error())
	}
	byHost := map[string]bool{}
	for i := range r.Platforms {
		p := &r.Platforms[i]
		if p.Platform == "" || p.AccountType == "" || len(p.Hosts) == 0 || len(p.HandlePatterns) == 0 ||
			!strings.HasPrefix(p.Source, "https://") {
			panic("account_platforms.json: " + p.Platform +
				" needs a platform, account_type, at least one host and handle pattern, and a documentation source")
		}
		for _, h := range p.Hosts {
			if byHost[h] {
				panic("account_platforms.json: host " + h + " is claimed by more than one platform")
			}
			byHost[h] = true
		}
		for _, pat := range p.HandlePatterns {
			re := regexp.MustCompile(pat)
			if re.NumSubexp() < 1 {
				panic("account_platforms.json: " + p.Platform + " handle pattern must capture the handle: " + pat)
			}
			p.res = append(p.res, re)
		}
		p.reserved = map[string]bool{}
		for _, name := range p.Reserved {
			p.reserved[strings.ToLower(name)] = true
		}
	}

	return r
})

// AccountEntry is one platform account derived from a stored URL.
type AccountEntry struct {
	Platform string `json:"platform"`
	Type     string `json:"type"`
	Handle   string `json:"handle"`
	URL      string `json:"url"`
}

// AccountsReport is the result of the accounts lens.
type AccountsReport struct {
	lensBase
	Accounts []AccountEntry `json:"accounts"`
	// ByPlatform counts the accounts on each platform, most first.
	ByPlatform []ChangeGroup `json:"by_platform,omitempty"`
}

// FindAccounts lists the platform accounts a domain or organization has,
// computed from the profile URLs stored for it. It reads only.
func FindAccounts(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (AccountsReport, error) {
	g = graph.Cached(g)
	var out AccountsReport
	s, err := newScope(ctx, g, schema, root, limits, LensAccounts)
	if err != nil {
		return out, err
	}

	urls, err := s.ownedURLs()
	if err != nil {
		return out, err
	}

	rules := loadAccountRules()
	byPlatform := map[string]*ChangeGroup{}
	var order []string
	seen := map[string]bool{}

	for _, u := range urls {
		platform, entry, ok := matchAccount(rules, urlRaw(u))
		if !ok {
			continue
		}
		key := entry.Platform + "\x00" + strings.ToLower(entry.Handle)
		if seen[key] {
			continue
		}
		seen[key] = true
		out.Accounts = append(out.Accounts, entry)

		g, ok := byPlatform[platform]
		if !ok {
			g = &ChangeGroup{Key: platform}
			byPlatform[platform] = g
			order = append(order, platform)
		}
		g.Count++
		if len(g.Examples) < subdomainsExamples {
			graph.AddUnique(&g.Examples, entry.Handle)
		}
	}

	sort.Slice(out.Accounts, func(i, j int) bool {
		if out.Accounts[i].Platform != out.Accounts[j].Platform {
			return out.Accounts[i].Platform < out.Accounts[j].Platform
		}
		return out.Accounts[i].Handle < out.Accounts[j].Handle
	})
	out.ByPlatform = make([]ChangeGroup, 0, len(order))
	for _, k := range order {
		out.ByPlatform = append(out.ByPlatform, *byPlatform[k])
	}
	sort.SliceStable(out.ByPlatform, func(i, j int) bool {
		if out.ByPlatform[i].Count != out.ByPlatform[j].Count {
			return out.ByPlatform[i].Count > out.ByPlatform[j].Count
		}
		return out.ByPlatform[i].Key < out.ByPlatform[j].Key
	})
	out.lensBase = s.base()
	return out, nil
}

// matchAccount recognizes a platform account in a URL: its host names the
// platform and its path yields the handle. It returns false when no platform
// matches or the path is a site page rather than an account.
func matchAccount(rules accountRules, raw string) (string, AccountEntry, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", AccountEntry{}, false
	}
	host := strings.ToLower(u.Hostname())
	host = strings.TrimPrefix(host, "www.")

	for i := range rules.Platforms {
		p := &rules.Platforms[i]
		if !hostMatches(host, p.Hosts) {
			continue
		}
		for _, re := range p.res {
			m := re.FindStringSubmatch(u.Path)
			if m == nil || m[1] == "" {
				continue
			}
			if p.reserved[strings.ToLower(m[1])] {
				continue
			}
			return p.Platform, AccountEntry{Platform: p.Platform, Type: p.AccountType, Handle: m[1], URL: raw}, true
		}
	}

	return "", AccountEntry{}, false
}

// hostMatches reports whether a URL host is one of a platform's hosts,
// matching the host itself and any subdomain of it.
func hostMatches(host string, hosts []string) bool {
	for _, h := range hosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// Text implements Report.
func (r AccountsReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}

	fmt.Fprintf(&b, "Platform accounts of %s: %d account(s) on %d platform(s) (%d reads).\n",
		subject, len(r.Accounts), len(r.ByPlatform), r.Reads)

	if len(r.Accounts) == 0 {
		b.WriteString("\nNo platform account is recognizable from the stored URLs.\n")
		return b.String()
	}

	b.WriteString("\n")
	for _, a := range r.Accounts {
		fmt.Fprintf(&b, "  %s: %s (%s)\n", a.Platform, a.Handle, a.URL)
	}

	b.WriteString("\nThese are accounts derived from stored profile URLs, not a live lookup." + r.partialNote() + "\n")
	return b.String()
}

// Facts implements Report.
func (r AccountsReport) Facts() []string {
	out := make([]string, 0, len(r.Accounts))
	for _, a := range r.Accounts {
		out = append(out, a.Platform+" account "+a.Handle)
	}
	return out
}
