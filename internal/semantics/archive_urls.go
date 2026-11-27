// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	"encoding/json"
	"path"
	"strings"
	"sync"
)

// ArchiveURLRules says which archived URLs the web-archive collectors keep as
// URL assets. Loaded from archive_urls.json; see that file's _about.
type ArchiveURLRules struct {
	License          string   `json:"_license"`
	About            string   `json:"_about"`
	MaxURLsPerDomain int      `json:"max_urls_per_domain"`
	StaticExtensions []string `json:"static_extensions"`
	Source           string   `json:"source"`
	static           map[string]bool
}

var loadArchiveURLRules = sync.OnceValue(func() ArchiveURLRules {
	var r ArchiveURLRules
	dec := json.NewDecoder(bytes.NewReader(File("archive_urls.json")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		panic("archive_urls.json: " + err.Error())
	}
	if r.MaxURLsPerDomain <= 0 || len(r.StaticExtensions) == 0 || !strings.HasPrefix(r.Source, "https://") {
		panic("archive_urls.json: max_urls_per_domain, static_extensions and an https source are required")
	}

	r.static = make(map[string]bool, len(r.StaticExtensions))
	for _, ext := range r.StaticExtensions {
		if !strings.HasPrefix(ext, ".") {
			panic("archive_urls.json: static extension " + ext + " must start with a dot")
		}
		r.static[strings.ToLower(ext)] = true
	}

	return r
})

// ArchiveURLs returns the archived-URL rules.
func ArchiveURLs() ArchiveURLRules { return loadArchiveURLRules() }

// IsStaticPath reports whether a URL path names a static file (an image,
// stylesheet, font or media file) the archive collectors do not keep.
func (r ArchiveURLRules) IsStaticPath(p string) bool {
	return r.static[strings.ToLower(path.Ext(p))]
}
