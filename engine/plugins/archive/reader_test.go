// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// inline does an archive's work at once, so a test sees its results when
// check returns. A retry comes after the test unless waits is set; then it
// is done at once too and its wait kept.
type inline struct{ waits *[]time.Duration }

func (inline) Enqueue(sess et.Session, _, _, _ string, work func(context.Context)) {
	work(sess.Ctx())
}

func (q inline) EnqueueAfter(sess et.Session, _, _, _ string, after time.Duration, work func(context.Context)) {
	if q.waits == nil {
		return
	}
	*q.waits = append(*q.waits, after)
	work(sess.Ctx())
}

// An archive that does not answer is asked again after each retry wait, and
// no more once it answers.
func TestArchiveRetries(t *testing.T) {
	sess := plugintest.NewSession(t)
	e := &et.Event{Session: sess, Entity: sess.Asset(t, &oamdns.FQDN{Name: "owasp.org"})}

	for _, tc := range []struct {
		answerOn int
		calls    int
		waits    []time.Duration
	}{
		{answerOn: 1, calls: 1},
		{answerOn: 2, calls: 2, waits: archiveRetries[:1]},
		{answerOn: 99, calls: 3, waits: archiveRetries},
	} {
		var waits []time.Duration
		calls := 0
		enqueue(inline{waits: &waits}, e, "Wayback", func(context.Context, *et.Event) bool {
			calls++
			return calls >= tc.answerOn
		})
		if calls != tc.calls || !slices.Equal(waits, tc.waits) {
			t.Errorf("answer on try %d: %d tries after waits %v, want %d after %v", tc.answerOn, calls, waits,
				tc.calls, tc.waits)
		}
	}
}
