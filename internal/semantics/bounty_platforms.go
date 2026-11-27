// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed bounty_platforms.json
var bountyPlatformsJSON []byte

// BountyPlatform is one public bug-bounty platform whose program scopes are
// read. Loaded from bounty_platforms.json; see that file's _about.
type BountyPlatform struct {
	Key          string   `json:"key"`
	Title        string   `json:"title"`
	Feed         string   `json:"feed"`
	HandleFields []string `json:"handle_fields"`
	CompanyField string   `json:"company_field,omitempty"`
	Page         string   `json:"page"`
	Hosts        []string `json:"hosts"`
	TXTPrefix    string   `json:"txt_prefix,omitempty"`
	Source       string   `json:"source"`
}

// ProgramPage returns the page of the program with handle when the feed gives
// none.
func (p BountyPlatform) ProgramPage(handle string) string {
	return strings.ReplaceAll(p.Page, "{handle}", handle)
}

// OwnsHost reports whether host is one of the platform's program-page hosts or
// a name below one.
func (p BountyPlatform) OwnsHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, h := range p.Hosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

type bountyPlatforms struct {
	License   string           `json:"_license"`
	About     string           `json:"_about"`
	Platforms []BountyPlatform `json:"platforms"`
}

var loadBountyPlatforms = sync.OnceValue(func() []BountyPlatform {
	var c bountyPlatforms
	dec := json.NewDecoder(bytes.NewReader(bountyPlatformsJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("bounty_platforms.json: " + err.Error())
	}
	if len(c.Platforms) == 0 {
		panic("bounty_platforms.json: no platforms")
	}

	seen := map[string]bool{}
	for _, p := range c.Platforms {
		if p.Key == "" || seen[p.Key] || strings.Contains(p.Key, ":") || p.Title == "" ||
			!strings.HasPrefix(p.Feed, "https://") || len(p.HandleFields) == 0 ||
			!strings.Contains(p.Page, "{handle}") || len(p.Hosts) == 0 || !strings.HasPrefix(p.Source, "https://") {
			panic("bounty_platforms.json: each platform needs a unique key without ':', title, https feed, " +
				"handle_fields, a page with {handle}, hosts and an https source")
		}
		seen[p.Key] = true
	}

	return c.Platforms
})

// BountyPlatforms returns the bug-bounty platform catalog.
func BountyPlatforms() []BountyPlatform { return loadBountyPlatforms() }

// BountyPlatformByKey returns the platform with key.
func BountyPlatformByKey(key string) (BountyPlatform, bool) {
	for _, p := range loadBountyPlatforms() {
		if p.Key == key {
			return p, true
		}
	}
	return BountyPlatform{}, false
}
