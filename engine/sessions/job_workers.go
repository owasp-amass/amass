// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/asset-db/repository"
)

// workerLeft notes a worker that left the session's job, with the main
// model's requests it made, which its lease no longer reports.
func (s *Session) workerLeft(wr workerRecord) {
	if wr.Worker == "" {
		return
	}
	s.addWorker(wr.Worker)
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	if s.left == nil {
		s.left = map[string]int64{}
	}
	s.left[wr.Worker] = wr.ModelCalls
}

// Workers reports the workers of the session's job, by session: whether
// each still holds its lease, its background work, the main model's
// requests it made, and the items it holds and did. It is nil when the
// database keeps no jobs.
func (s *Session) Workers() []et.WorkerStats {
	q, ok := s.db.(repository.WorkQueue)
	if s.work == nil || !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	counts, err := q.CountWorkByOwner(ctx, s.job)
	if err != nil {
		return nil
	}

	s.jobMu.Lock()
	workers := slices.Clone(s.workers)
	left := maps.Clone(s.left)
	s.jobMu.Unlock()
	byWorker := map[string]*et.WorkerStats{}
	for _, w := range workers {
		ws := &et.WorkerStats{Worker: w, ModelCalls: left[w]}
		if l, ok := s.leases.Find(workerLease(s.job, w)); ok {
			var d workerData
			ws.Live = true
			if json.Unmarshal(l.Data, &d) == nil {
				ws.Background, ws.ModelCalls = d.Background, d.ModelCalls
			}
		}
		if w == s.id.String() {
			// the session's own count, not its lease's last renewal
			ws.ModelCalls = s.breaker.Requests()
		}
		byWorker[w] = ws
	}
	// a backlog owner is the session's ID and the asset type it claimed
	for owner, c := range counts {
		w, _, _ := strings.Cut(owner, ":")
		ws := byWorker[w]
		if ws == nil {
			ws = &et.WorkerStats{Worker: w}
			byWorker[w] = ws
		}
		ws.Leased += c.Leased
		ws.Done += c.Done
	}

	out := make([]et.WorkerStats, 0, len(byWorker))
	for _, ws := range byWorker {
		out = append(out, *ws)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Worker < out[j].Worker })
	return out
}
