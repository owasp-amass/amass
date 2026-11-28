// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

// archiveBudget bounds the reading of one domain in one archive: its pages,
// retries and waits.
const archiveBudget = 15 * time.Minute

// archiveRetries are the waits before an archive is asked again, in the same
// run, about a domain it did not answer for. A retry still due when the run's
// other work is done waits no longer than the background hold.
var archiveRetries = []time.Duration{5 * time.Minute, 15 * time.Minute}

// queuer takes an archive's work on a domain.
type queuer interface {
	Enqueue(sess et.Session, key, plugin, what string, work func(context.Context))
	EnqueueAfter(sess et.Session, key, plugin, what string, after time.Duration, work func(context.Context))
}

// newReader returns the lane one archive's queries are read in beside the
// pipeline, one domain at a time (support.BackgroundLane).
func newReader() queuer {
	return support.NewBackgroundLane("archive", archiveBudget)
}

// enqueue queues the domain in e for the archive's work, which reports
// whether the archive answered; one that did not is asked again after each
// of archiveRetries.
func enqueue(q queuer, e *et.Event, plugin string, work func(context.Context, *et.Event) bool) {
	enqueueAttempt(q, e, plugin, work, 0)
}

func enqueueAttempt(q queuer, e *et.Event, plugin string, work func(context.Context, *et.Event) bool, attempt int) {
	what := e.Entity.Asset.Key()
	job := func(ctx context.Context) {
		if work(ctx, e) || attempt >= len(archiveRetries) || e.Session.Done() {
			return
		}
		after := archiveRetries[attempt]
		e.Session.Log().Info("archive will be asked again", "domain", what, "in", after.String(),
			slog.Group("plugin", "name", plugin, "handler", plugin+"-Handler"))
		enqueueAttempt(q, e, plugin, work, attempt+1)
	}

	if attempt == 0 {
		q.Enqueue(e.Session, e.Entity.ID, plugin, what, job)
		return
	}
	q.EnqueueAfter(e.Session, e.Entity.ID, plugin, what, archiveRetries[attempt-1], job)
}
