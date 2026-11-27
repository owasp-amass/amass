// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"path/filepath"
	"testing"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/ai"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
)

// A job's workers report the main model's requests each made, including a
// worker that left the job to the others.
func TestWorkersReportModelCalls(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	first := jobSession(t, repo, jobConfigFor("example.com", "k1"))
	first.breaker = &ai.ModelBreaker{}
	start(t, first, "")
	second := jobSession(t, repo, jobConfigFor("example.com", "k2"))
	second.breaker = &ai.ModelBreaker{}
	start(t, second, "")
	if !second.joined {
		t.Fatal("the second session did not join")
	}

	first.breaker.Record(nil)
	second.breaker.Record(nil)
	second.breaker.Record(nil)
	leave(second)

	recs, err := first.work.Read(0)
	if err != nil {
		t.Fatal(err)
	}
	first.applyJobRecords(recs)
	byWorker := map[string]et.WorkerStats{}
	for _, ws := range first.Workers() {
		byWorker[ws.Worker] = ws
	}
	if ws := byWorker[first.id.String()]; !ws.Live || ws.ModelCalls != 1 {
		t.Errorf("the first worker: %+v", ws)
	}
	if ws := byWorker[second.id.String()]; ws.Live || ws.ModelCalls != 2 {
		t.Errorf("the worker that left: %+v", ws)
	}
	if jobEnded(t, first) {
		t.Error("the job ended while a worker remained")
	}
}
