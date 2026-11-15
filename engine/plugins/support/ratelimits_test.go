// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"testing"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"golang.org/x/time/rate"
)

func TestWaitLimitCountsTheSessionsWaits(t *testing.T) {
	u := &et.NetUsage{}
	ctx := et.WithNetUsage(context.Background(), u)
	lim := rate.NewLimiter(rate.Every(20*time.Millisecond), 1)

	for range 3 {
		if err := WaitLimit(ctx, lim); err != nil {
			t.Fatal(err)
		}
	}

	var waits int
	var took time.Duration
	for _, w := range u.Waits() {
		waits += w.Waits
		took += w.Took
	}
	if waits != 3 || took < 30*time.Millisecond {
		t.Errorf("counted %d waits taking %s, want 3 taking about 40ms", waits, took)
	}

	// A cancelled wait is returned as before, and still counted.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := WaitLimit(cctx, rate.NewLimiter(rate.Every(time.Hour), 0)); err == nil {
		t.Error("a cancelled wait succeeded")
	}

	// Without a session's counters, waiting works as before.
	if err := WaitLimit(context.Background(), rate.NewLimiter(rate.Inf, 1)); err != nil {
		t.Error(err)
	}
}
