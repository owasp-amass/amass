// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	dbt "github.com/owasp-amass/asset-db/types"
)

// WorkTopic is the journal topic the workers of a job share its work
// through: the job and its workers (jobs.go), the scope entries they add and
// the admission decisions they make.
const WorkTopic = "work"

// workFollowInterval is how often a session reads what the job's other
// workers recorded.
const workFollowInterval = 2 * time.Second

// shareWork shares the session's scope with its job's other workers and
// follows what they record, when the database keeps the work topic.
func (s *Session) shareWork() {
	if s.work == nil {
		return
	}
	sc, _ := s.scope.(*scope.Scope)
	if sc != nil {
		sc.Replicate(s.work, s.leases, s.job, s.id.String())
	}
	go s.followWork(sc)
}

// followWork reads the job's records in the work topic until the session
// ends, giving the scope its records and taking the job's own; other jobs'
// records are not read. A worker that joined a job reads it from the
// start, so it replays the job's scope and decisions.
func (s *Session) followWork(sc *scope.Scope) {
	t := time.NewTicker(workFollowInterval)
	defer t.Stop()

	var seq int64
	for {
		recs, err := s.work.ReadWhere(dbt.JournalFilter{Key: s.job}, seq)
		switch {
		case err != nil:
			s.log.Warn("the job's shared work was not read", slog.String("error", err.Error()))
		case len(recs) > 0:
			seq = recs[len(recs)-1].Seq
			if sc != nil {
				sc.Apply(recs)
			}
			s.applyJobRecords(recs)
		}

		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
	}
}
