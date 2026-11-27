// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package collect

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"time"
)

// runKind is the kind of a run's record in the runs topic.
const runKind = "run"

// runLeaseTTL is how long a run's lease lasts unless its supervisor renews
// it: a manager that exits leaves its runs to the next to resume them.
const runLeaseTTL = 2 * time.Minute

// runLease names the lease of the manager supervising a run.
func runLease(id string) string { return "run:" + id }

// load reads the runs recorded so far: once from the file, or, from the
// database's runs topic, those recorded since the last read, so another
// manager's runs appear. The caller holds m.mu.
func (m *Manager) load() {
	if !m.loaded {
		m.loaded = true
		m.runs = map[string]*Run{}
		m.cancels = map[string]context.CancelFunc{}
		if m.RunTopic == nil {
			m.loadFile()
			return
		}
		m.importFile()
	}
	if m.RunTopic == nil {
		return
	}

	recs, err := m.RunTopic.Read(m.runSeq)
	if err != nil {
		return
	}
	for _, rec := range recs {
		m.runSeq = rec.Seq
		var r Run
		if rec.Kind != runKind || json.Unmarshal(rec.Data, &r) != nil || r.ID == "" {
			continue
		}
		// a run this manager supervises is as it says
		if _, mine := m.cancels[r.ID]; mine {
			continue
		}
		m.runs[r.ID] = &r
	}
}

// fileRuns reads the runs recorded in the Journal file.
func (m *Manager) fileRuns() []Run {
	if m.Journal == "" {
		return nil
	}
	f, err := os.Open(m.Journal)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var out []Run
	lines := bufio.NewScanner(f)
	lines.Buffer(make([]byte, 64<<10), 1<<20)
	for lines.Scan() {
		var r Run
		if json.Unmarshal(lines.Bytes(), &r) == nil && r.ID != "" {
			out = append(out, r)
		}
	}
	return out
}

func (m *Manager) loadFile() {
	for _, r := range m.fileRuns() {
		m.runs[r.ID] = &r
	}
}

// importFile moves the runs of a Journal file into an empty runs topic, so
// the runs recorded before the database kept them are still listed and
// resumed.
func (m *Manager) importFile() {
	if recs, err := m.RunTopic.Read(0); err != nil || len(recs) > 0 {
		return
	}
	for _, r := range m.fileRuns() {
		_, _ = m.RunTopic.Append(runKind, r.ID, r)
	}
}

// record appends a run's state to the runs topic or the journal file. The
// caller holds m.mu.
func (m *Manager) record(r *Run) {
	if m.RunTopic != nil {
		_, _ = m.RunTopic.Append(runKind, r.ID, r)
		return
	}
	if m.Journal == "" {
		return
	}

	data, err := json.Marshal(r)
	if err != nil {
		return
	}

	f, err := os.OpenFile(m.Journal, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}

	_, _ = f.Write(append(data, '\n'))
	_ = f.Close()
}
