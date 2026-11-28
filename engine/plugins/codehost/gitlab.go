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

// parseGitLabGroup reads a GitLab group's profile and its numeric ID.
func parseGitLabGroup(data []byte) (profile, int, bool) {
	var g struct {
		ID       int    `json:"id"`
		Name     string `json:"name"`
		FullPath string `json:"full_path"`
		WebURL   string `json:"web_url"`
	}
	if json.Unmarshal(data, &g) != nil || g.ID == 0 || g.FullPath == "" {
		return profile{}, 0, false
	}
	return profile{host: "gitlab", handle: g.FullPath, page: g.WebURL, name: strings.TrimSpace(g.Name)}, g.ID, true
}

// parseGitLabProjects reads the projects of a group that are not forks.
func parseGitLabProjects(data []byte, limit int) []repository {
	var ps []struct {
		WebURL     string          `json:"web_url"`
		ForkedFrom json.RawMessage `json:"forked_from_project"`
	}
	if json.Unmarshal(data, &ps) != nil {
		return nil
	}
	var out []repository
	for _, p := range ps {
		if p.WebURL == "" || (len(p.ForkedFrom) > 0 && string(p.ForkedFrom) != "null") {
			continue
		}
		if out = append(out, repository{page: p.WebURL}); len(out) == limit {
			break
		}
	}
	return out
}

// gitlab reads a GitLab group the organization's stored URLs name. GitLab
// groups name no website, so only a named group is read.
func (c *codeHosts) gitlab(e *et.Event, owner *dbt.Entity, apex string, cand candidate) {
	data, err := support.FetchBody(e, c.catalog.GitLab.API+"/groups/"+url.PathEscape(cand.handle), c.rlimit, maxBody)
	if err != nil {
		return
	}
	p, id, ok := parseGitLabGroup(data)
	if !ok {
		return
	}

	limit := c.catalog.MaxRepositories
	var repos []repository
	u := fmt.Sprintf("%s/groups/%d/projects?include_subgroups=true&archived=false&per_page=%d", c.catalog.GitLab.API,
		id, min(limit, 100))
	if data, err := support.FetchBody(e, u, c.rlimit, maxBody); err == nil {
		repos = parseGitLabProjects(data, limit)
	}
	c.store(e, owner, apex, p, repos, nil)
}
