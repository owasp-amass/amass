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

//go:embed bucket_providers.json
var bucketProvidersJSON []byte

// BucketSignature matches an HTTP response by status code and body substrings.
// A response matches when its status is one of Status (when Status is set) and
// its body contains one of BodyContains (when BodyContains is set).
type BucketSignature struct {
	Status       []int    `json:"status"`
	BodyContains []string `json:"body_contains"`
}

// BucketProvider describes one public object-storage provider: the host
// patterns that identify a bucket endpoint and capture the bucket or storage
// account name, the probe endpoint template (placeholders {host} and {bucket}),
// and the response signatures of a missing bucket and of a world-readable
// listing. Loaded from bucket_providers.json; see that file's _about.
type BucketProvider struct {
	Key           string          `json:"key"`
	Organization  string          `json:"organization"`
	Patterns      []string        `json:"patterns"`
	Endpoint      string          `json:"endpoint"`
	Method        string          `json:"method"`
	NotFound      BucketSignature `json:"not_found"`
	PublicListing BucketSignature `json:"public_listing"`
	Source        string          `json:"source"`
	compiled      []*regexp.Regexp
}

type bucketProviders struct {
	License   string           `json:"_license"`
	About     string           `json:"_about"`
	Providers []BucketProvider `json:"providers"`
}

var loadBucketProviders = sync.OnceValue(func() []BucketProvider {
	var c bucketProviders
	dec := json.NewDecoder(bytes.NewReader(bucketProvidersJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("bucket_providers.json: " + err.Error())
	}
	if len(c.Providers) == 0 {
		panic("bucket_providers.json: no providers")
	}

	for i := range c.Providers {
		p := &c.Providers[i]
		if p.Key == "" || p.Organization == "" || p.Endpoint == "" || len(p.Patterns) == 0 ||
			!strings.HasPrefix(p.Source, "https://") {
			panic("bucket_providers.json: each provider needs key, organization, endpoint, patterns and an https source")
		}
		if len(p.NotFound.Status) == 0 && len(p.NotFound.BodyContains) == 0 {
			panic("bucket_providers.json: " + p.Key + " needs a not_found signature")
		}
		for _, pat := range p.Patterns {
			p.compiled = append(p.compiled, regexp.MustCompile(pat))
		}
	}

	return c.Providers
})

// BucketProviders returns the object-storage provider catalog.
func BucketProviders() []BucketProvider { return loadBucketProviders() }

// MatchBucketHost reports whether host is a known object-storage bucket
// endpoint, returning the matching provider and the bucket or storage-account
// name captured from it. Matching is purely on the host string, so it reads
// bucket endpoints out of names already stored (CNAME targets, cert SANs)
// without any network request.
func MatchBucketHost(host string) (provider BucketProvider, name string, ok bool) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, p := range loadBucketProviders() {
		for _, re := range p.compiled {
			m := re.FindStringSubmatch(host)
			if m == nil {
				continue
			}

			for i, sub := range re.SubexpNames() {
				if (sub == "bucket" || sub == "account") && i < len(m) {
					name = m[i]
					break
				}
			}

			return p, name, true
		}
	}

	return BucketProvider{}, "", false
}
