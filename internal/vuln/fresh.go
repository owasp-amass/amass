// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package vuln

import (
	"context"
	"time"
)

// freshCheck is how often KeepFresh checks whether the data is stale.
var freshCheck = time.Hour

// KeepFresh keeps the data file at path current until ctx ends: every hour
// it refreshes the data once it is older than maxAge or the catalog gained
// products, as Stale decides. A failed refresh is retried at the next
// check, so NVD and CISA see at most one update per maxAge when it works.
// logf reports each refresh.
func KeepFresh(ctx context.Context, path, apiKey string, maxAge time.Duration,
	logf func(format string, args ...any)) {
	if logf == nil {
		logf = func(string, ...any) {}
	}

	t := time.NewTicker(freshCheck)
	defer t.Stop()
	for {
		if Stale(path, maxAge, time.Now()) {
			u := &Updater{APIKey: apiKey}
			if res, err := u.Update(ctx, path); err != nil {
				logf("vulnerability data refresh: %v", err)
			} else {
				logf("vulnerability data refreshed: %d CVEs, %d known exploited", res.CVEs, res.KEV)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
