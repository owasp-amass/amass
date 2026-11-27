// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scrape

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

// fetchPage requests one page within the plugin's rate limit and the
// session's network share, and returns its body only when the site answered
// 200 OK: a site that refuses, rate limits or fails is not asked again for
// more pages.
func fetchPage(sess et.Session, rlimit *rate.Limiter, url string) (string, bool) {
	if err := support.WaitLimit(sess.Ctx(), rlimit); err != nil {
		return "", false
	}

	sess.NetSem().Acquire()
	defer sess.NetSem().Release()

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, sess.Clients().General, &amasshttp.Request{URL: url})
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK || resp.Body == "" {
		return "", false
	}

	return resp.Body, true
}

// scrapePages requests the pages of a paged search in order, up to pages of
// them, and returns the in-scope subdomain names found. It stops at the first
// page that is not served or adds no new name, since later pages would only
// repeat it.
func scrapePages(e *et.Event, rlimit *rate.Limiter, pages int, url func(page int) string) []string {
	seen := map[string]struct{}{}
	var names []string

	for i := 1; i <= pages; i++ {
		body, ok := fetchPage(e.Session, rlimit, url(i))
		if !ok {
			break
		}

		added := false
		for _, n := range support.ScrapeSubdomainNames(body) {
			name := strings.ToLower(strings.TrimSpace(n))
			if _, found := seen[name]; found || name == "" {
				continue
			}

			seen[name], added = struct{}{}, true
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: name}, 0); conf > 0 {
				names = append(names, name)
			}
		}
		if !added {
			break
		}
	}

	return names
}
