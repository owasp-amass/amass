// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
)

//go:embed account_platforms.json
var accountPlatformsJSON []byte

// AccountPlatform is a public platform whose profile URLs name an account
// (a code host, a social network). Loaded from account_platforms.json; see
// that file's _about.
type AccountPlatform struct {
	Platform       string   `json:"platform"`
	AccountType    string   `json:"account_type"`
	Hosts          []string `json:"hosts"`
	HandlePatterns []string `json:"handle_patterns"`
	Reserved       []string `json:"reserved"`
	Source         string   `json:"source"`
	patterns       []*regexp.Regexp
	reserved       map[string]bool
}

type accountPlatformCatalog struct {
	License   string            `json:"_license"`
	About     string            `json:"_about"`
	Platforms []AccountPlatform `json:"platforms"`
}

var loadAccountPlatforms = sync.OnceValue(func() []AccountPlatform {
	var c accountPlatformCatalog
	dec := json.NewDecoder(bytes.NewReader(accountPlatformsJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("account_platforms.json: " + err.Error())
	}

	byHost := map[string]bool{}
	for i := range c.Platforms {
		p := &c.Platforms[i]
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
			p.patterns = append(p.patterns, re)
		}
		p.reserved = map[string]bool{}
		for _, name := range p.Reserved {
			p.reserved[strings.ToLower(name)] = true
		}
	}
	return c.Platforms
})

// AccountPlatforms returns the account platform catalog.
func AccountPlatforms() []AccountPlatform { return loadAccountPlatforms() }

// AccountPlatformHost reports whether a host is one of the platforms' own,
// where many unrelated accounts live.
func AccountPlatformHost(host string) bool {
	ps := loadAccountPlatforms()
	for i := range ps {
		if ps[i].OwnsHost(host) {
			return true
		}
	}
	return false
}

// OwnsHost reports whether a host is the platform's, or under one of its
// hosts.
func (p *AccountPlatform) OwnsHost(host string) bool { return hostUnder(host, p.Hosts) }

// Patterns returns the compiled handle patterns, in order.
func (p *AccountPlatform) Patterns() []*regexp.Regexp { return p.patterns }

// IsReserved reports whether a first path segment is a site page rather than
// an account.
func (p *AccountPlatform) IsReserved(segment string) bool {
	return p.reserved[strings.ToLower(segment)]
}
