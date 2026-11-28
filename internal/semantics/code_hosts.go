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

//go:embed code_hosts.json
var codeHostsJSON []byte

// CodeHost is one code host's API.
type CodeHost struct {
	API             string `json:"api"`
	Page            string `json:"page"`
	Source          string `json:"source"`
	RequestsPerHour int    `json:"requests_per_hour,omitempty"`
}

// CodeHosts is how an organization's code-host organizations are read.
// Loaded from code_hosts.json; see that file's _about.
type CodeHosts struct {
	License         string   `json:"_license"`
	About           string   `json:"_about"`
	GitHub          CodeHost `json:"github"`
	GitLab          CodeHost `json:"gitlab"`
	MaxRepositories int      `json:"max_repositories"`
	MaxMembers      int      `json:"max_members"`
}

var loadCodeHosts = sync.OnceValue(func() CodeHosts {
	var c CodeHosts
	dec := json.NewDecoder(bytes.NewReader(codeHostsJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("code_hosts.json: " + err.Error())
	}
	for _, h := range []CodeHost{c.GitHub, c.GitLab} {
		if !strings.HasPrefix(h.API, "https://") || !strings.HasPrefix(h.Page, "https://") || h.Source == "" {
			panic("code_hosts.json: each code host needs an https api and page, and a source")
		}
	}
	if c.GitHub.RequestsPerHour <= 0 || c.MaxRepositories <= 0 || c.MaxMembers < 0 {
		panic("code_hosts.json: github.requests_per_hour and max_repositories must be positive")
	}
	return c
})

// CodeHostCatalog returns how code-host organizations are read.
func CodeHostCatalog() CodeHosts { return loadCodeHosts() }
