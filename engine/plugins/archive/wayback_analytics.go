// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"net/http"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/fingerprint"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// snapshotYearsAgo are how far back the domain's archived homepage is read
// for analytics identifiers. A site often drops an identifier when it
// redesigns while its other sites keep it; an archived copy still shows the
// identifier the organization used. Older copies are not read: the further
// back, the likelier the domain had another owner.
var snapshotYearsAgo = []int{1, 3, 5}

// snapshotTimeout bounds one archived page request.
const snapshotTimeout = time.Minute

// analytics reads the domain's homepage as the Wayback Machine archived it
// snapshotYearsAgo, and stores each analytics or tag identifier found as a
// fingerprint of the homepage URL, the way a live page's are stored, so the
// ownership lens can match the identifier on pages the organization does not
// yet own. The archive serves the capture nearest the date asked for; id_
// asks for the page as captured, without the archive's toolbar or rewritten
// links. A refused or failed page is skipped.
func (w *wayback) analytics(ctx context.Context, e *et.Event, domain string) int {
	home := "https://" + domain + "/"

	seen := map[string]bool{}
	var ids []string
	for _, years := range snapshotYearsAgo {
		ts := time.Now().UTC().AddDate(-years, 0, 0).Format("20060102") + "000000"
		resp, err := request(ctx, e, w.rlimit, w.backoff, snapshotTimeout, w.SnapshotURL+ts+"id_/"+home)
		if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
			continue
		}

		for _, id := range fingerprint.AnalyticsIDs(resp.Body) {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return 0
	}

	wctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Minute)
	defer cancel()

	u := support.RawURLToOAM(home)
	if u == nil {
		return 0
	}
	urlEnt, err := e.Session.DB().CreateAsset(wctx, u)
	if err != nil || urlEnt == nil {
		return 0
	}
	support.AddSource(wctx, e.Session, urlEnt, w.source)
	if dom, err := e.Session.DB().CreateAsset(wctx, &oamdns.FQDN{Name: domain}); err == nil && dom != nil {
		support.Link(wctx, e.Session, urlEnt, "domain", dom, w.source)
	}

	var stored int
	for _, id := range ids {
		if support.StoreFingerprint(e, urlEnt, w.source, fingerprint.AnalyticsID, id) {
			stored++
		}
	}
	return stored
}
