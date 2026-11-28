// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
)

// A job runs beside the pipeline as the session's background work, once per
// key however often it is queued; a run with nothing else left gets it only
// within its background hold.
func TestBackgroundLane(t *testing.T) {
	for _, tc := range []struct {
		hold time.Duration
		runs int32
	}{{20 * time.Minute, 1}, {0, 0}} {
		sess := plugintest.NewSession(t)
		sess.Config().BackgroundHold = &tc.hold

		release := make(chan struct{})
		var runs atomic.Int32
		work := func(context.Context) {
			runs.Add(1)
			<-release
		}
		l := NewBackgroundLane("test", time.Minute)
		l.Enqueue(sess, "example.com", "Test", "example.com", work)
		l.Enqueue(sess, "example.com", "Test", "example.com", work)
		if tc.runs > 0 && sess.Stats().Background() < 1 {
			t.Errorf("hold %s: the queued job is not background work", tc.hold)
		}

		close(release)
		for deadline := time.Now().Add(5 * time.Second); sess.Stats().Background() != 0; {
			if time.Now().After(deadline) {
				t.Fatalf("hold %s: the background work was not finished", tc.hold)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if runs.Load() != tc.runs || sess.Stats().BackgroundDone() != 1 {
			t.Errorf("hold %s: ran %d times, %d units done", tc.hold, runs.Load(), sess.Stats().BackgroundDone())
		}
	}
}

// A job queued for later counts as background work from the start and runs
// once its wait has passed.
func TestBackgroundLaneEnqueueAfter(t *testing.T) {
	hold := 20 * time.Minute
	sess := plugintest.NewSession(t)
	sess.Config().BackgroundHold = &hold

	var runs atomic.Int32
	l := NewBackgroundLane("test", time.Minute)
	l.EnqueueAfter(sess, "owasp.org", "Test", "owasp.org", 50*time.Millisecond, func(context.Context) { runs.Add(1) })
	if sess.Stats().Background() < 1 {
		t.Error("the waiting job is not background work")
	}
	for deadline := time.Now().Add(5 * time.Second); runs.Load() == 0 || sess.Stats().Background() != 0; {
		if time.Now().After(deadline) {
			t.Fatalf("ran %d times, %d background units left", runs.Load(), sess.Stats().Background())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
