// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
)

// A pool skips a job at its cap on workers, and on a tie joins the older
// job.
func TestPoolChoosesJobsBelowTheirCap(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	q := repo.(repository.WorkQueue)
	enqueue := func(job string, n int) {
		t.Helper()
		for i := range n {
			if err := q.EnqueueWork(ctx, job, "FQDN", fmt.Sprintf("%s-%d", job, i)); err != nil {
				t.Fatal(err)
			}
		}
	}

	capped := jobConfigFor("capped.example", "k1")
	capped.Options[config.MaxJobWorkersOption] = 1
	full := jobSession(t, repo, capped)
	start(t, full, "")
	older := jobSession(t, repo, jobConfigFor("older.example", "k2"))
	start(t, older, "")
	newer := jobSession(t, repo, jobConfigFor("newer.example", "k3"))
	start(t, newer, "")
	// the capped job has the most queued work per worker
	enqueue(full.job, 5)
	enqueue(older.job, 2)
	enqueue(newer.job, 2)

	p := &pool{mgr: &manager{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, work: full.work,
		leases: full.leases, queue: q, runs: full.runs}
	if got := p.choose(ctx, nil); got != older.job {
		t.Errorf("the pool chose %s, not the older job below its cap (%s)", got, older.job)
	}
	if got := p.choose(ctx, map[string]bool{older.job: true}); got != newer.job {
		t.Errorf("the pool chose %s, not the job it does not work on (%s)", got, newer.job)
	}
	if n := jobMaxWorkers([]byte(`{"options":{"max_job_workers":3}}`)); n != 3 {
		t.Errorf("the cap read from a job record: %d", n)
	}
}
