// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

// archiveBudget bounds the reading of one domain in one archive: its pages,
// retries and waits.
const archiveBudget = 15 * time.Minute

// queuer takes an archive's work on a domain.
type queuer interface {
	Enqueue(sess et.Session, key, plugin, what string, work func(context.Context))
}

// newReader returns the lane one archive's queries are read in beside the
// pipeline, one domain at a time (support.BackgroundLane).
func newReader() queuer {
	return support.NewBackgroundLane("archive", archiveBudget)
}

// enqueue queues the domain in e for the archive's work.
func enqueue(q queuer, e *et.Event, plugin string, work func(context.Context, *et.Event)) {
	q.Enqueue(e.Session, e.Entity.ID, plugin, e.Entity.Asset.Key(), func(ctx context.Context) { work(ctx, e) })
}
