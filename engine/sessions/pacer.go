// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"log/slog"
	"sync"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/net/pacer"
)

var pacerOnce sync.Once

// connectPacer sends the data source pacer's state changes (a source paused,
// a source resumed) to the engine's log, and counts each wait it imposes in
// the network use of the session that waited, next to the rate-limit waits,
// as "pacer <host>". The pacer is shared by every session, so this is done
// once.
func connectPacer(log *slog.Logger) {
	pacerOnce.Do(func() {
		pacer.Default.SetLogger(log.WithGroup("plugin").With("name", "source-pacer"))
		pacer.Default.OnWait(func(ctx context.Context, host string, d time.Duration) {
			et.NetUsageFrom(ctx).Waited("pacer "+host, d)
		})
	})
}
