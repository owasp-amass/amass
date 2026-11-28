// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package codehost

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
)

// repository is a public repository of a code-host organization.
type repository struct {
	page, homepage string
}

// parseGitHubOrg reads a GitHub organization's profile, or false when the
// answer is not an organization's.
func parseGitHubOrg(data []byte, page string) (profile, bool) {
	var o struct {
		Login    string `json:"login"`
		Type     string `json:"type"`
		Name     string `json:"name"`
		Blog     string `json:"blog"`
		Email    string `json:"email"`
		Verified bool   `json:"is_verified"`
	}
	if json.Unmarshal(data, &o) != nil || o.Login == "" || !strings.EqualFold(o.Type, "Organization") {
		return profile{}, false
	}
	return profile{host: "github", handle: o.Login, page: page + o.Login, name: strings.TrimSpace(o.Name),
		website: strings.TrimSpace(o.Blog), email: strings.TrimSpace(o.Email), verified: o.Verified}, true
}

// parseGitHubRepos reads the public repositories of an organization that are
// not forks.
func parseGitHubRepos(data []byte, limit int) []repository {
	var rs []struct {
		HTMLURL  string `json:"html_url"`
		Homepage string `json:"homepage"`
		Fork     bool   `json:"fork"`
	}
	if json.Unmarshal(data, &rs) != nil {
		return nil
	}
	var out []repository
	for _, r := range rs {
		if r.Fork || r.HTMLURL == "" {
			continue
		}
		if out = append(out, repository{page: r.HTMLURL, homepage: strings.TrimSpace(r.Homepage)}); len(out) == limit {
			break
		}
	}
	return out
}

// parseGitHubMembers reads the logins of an organization's public members.
func parseGitHubMembers(data []byte, limit int) []string {
	var ms []struct {
		Login string `json:"login"`
	}
	if json.Unmarshal(data, &ms) != nil {
		return nil
	}
	var out []string
	for _, m := range ms {
		if m.Login != "" && len(out) < limit {
			out = append(out, m.Login)
		}
	}
	return out
}

// githubGet fetches a GitHub API path when the shared budget allows it.
func (c *codeHosts) githubGet(e *et.Event, path string) []byte {
	if !c.budget() {
		return nil
	}
	data, err := support.FetchBody(e, c.catalog.GitHub.API+path, c.rlimit, maxBody)
	if err != nil {
		return nil
	}
	return data
}

// github reads a GitHub organization. A guessed one is kept only when its
// profile's website or email is in the footprint.
func (c *codeHosts) github(e *et.Event, owner *dbt.Entity, apex string, f support.Footprint, cand candidate) {
	handle := url.PathEscape(cand.handle)
	p, ok := parseGitHubOrg(c.githubGet(e, "/orgs/"+handle), c.catalog.GitHub.Page)
	if !ok {
		return
	}
	domain := tie(f, p)
	if domain == "" && !cand.named {
		return
	}
	if domain == "" {
		domain = apex
	}

	limit := c.catalog.MaxRepositories
	repos := parseGitHubRepos(c.githubGet(e, fmt.Sprintf("/orgs/%s/repos?type=public&sort=pushed&per_page=%d",
		handle, min(limit, 100))), limit)
	var members []string
	if n := c.catalog.MaxMembers; n > 0 {
		members = parseGitHubMembers(c.githubGet(e, fmt.Sprintf("/orgs/%s/public_members?per_page=%d", handle,
			min(n, 100))), n)
	}
	c.store(e, owner, domain, p, repos, members)
}
