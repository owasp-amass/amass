// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/coord"
	"github.com/owasp-amass/asset-db/repository"
)

// ReviewEvent is separate from OAM. No edge is inserted automatically.
type ReviewEvent struct {
	ProposalID string    `json:"proposal_id"`
	Status     string    `json:"status"`
	Actor      string    `json:"actor"`
	At         time.Time `json:"at"`
}

// JournalTopic is the topic of the Asset Database's journal that keeps the
// review journal.
const JournalTopic = "review"

// Journal is the review journal: the proposals, the decisions about them
// and their undo records, the document readings and the AI's own
// decisions. It is kept in the Asset Database when that keeps a journal
// (OpenJournal), so every engine and machine on the database shares it, and
// otherwise in the file at Path, a JSON record per line. A Journal with only
// a Path is the file.
type Journal struct {
	Path string
	db   *coord.Topic
	mu   sync.Mutex
	// seq and lines cache what was read from the database: a read asks
	// only for the records after seq.
	seq   int64
	lines []json.RawMessage
	// fixed marks a read-only journal of given records (JournalOf).
	fixed bool
}

// JournalOf is a read-only journal of the given records, such as the first
// records of another journal's History, read with the same readers.
func JournalOf(lines []json.RawMessage) *Journal {
	return &Journal{lines: lines[:len(lines):len(lines)], fixed: true}
}

// OpenJournal is the review journal named path, kept in repo's database
// when the database keeps a journal (PostgreSQL and SQLite), otherwise in
// the file at path. With no path there is no journal: it returns nil.
func OpenJournal(path string, repo repository.Repository) *Journal {
	if strings.TrimSpace(path) == "" {
		return nil
	}

	return &Journal{Path: path, db: coord.Open(repo, JournalTopic)}
}

// Name says where the journal is kept, for messages.
func (j *Journal) Name() string {
	if j.Shared() {
		return "the Asset Database's journal"
	}
	return j.Path
}

// Shared reports whether the journal is kept in the Asset Database.
func (j *Journal) Shared() bool {
	return j != nil && j.db != nil
}

// Sibling is another topic of the Asset Database journal the journal is
// kept in, or nil when the journal is a file.
func (j *Journal) Sibling(topic string) *coord.Topic {
	if !j.Shared() {
		return nil
	}
	return &coord.Topic{Store: j.db.Store, Name: topic}
}

func (j *Journal) append(kind string, body any) error {
	if j != nil && j.fixed {
		return errors.New("the journal is read-only")
	}
	if j == nil || (j.Path == "" && j.db == nil) {
		return errors.New("journal path required")
	}
	if j.db != nil {
		return j.appendDB(kind, body)
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(j.Path), 0700); err != nil {
		return err
	}

	f, err := os.OpenFile(j.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }()
	data, err := json.Marshal(map[string]any{"kind": kind, "data": body})
	if err != nil {
		return err
	}
	if _, err = f.Write(append(data, '\n')); err != nil {
		return err
	}

	return f.Sync()
}

// appendDB appends a record to the database's journal, keyed by the ID of
// what it is about when it names one.
func (j *Journal) appendDB(kind string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	_, err = j.db.Append(kind, recordKey(data), json.RawMessage(data))
	return err
}

// recordKey is the ID a record is about: its id, or the proposal it
// decides.
func recordKey(data []byte) string {
	var ids struct {
		ID         string `json:"id"`
		ProposalID string `json:"proposal_id"`
	}
	if json.Unmarshal(data, &ids) != nil {
		return ""
	}
	if ids.ID != "" {
		return ids.ID
	}
	return ids.ProposalID
}

func (j *Journal) Submit(p Proposal) error {
	if p.ID == "" || p.Status != "proposed" {
		return errors.New("proposal must be proposed and have ID")
	}

	return j.append("proposal", p)
}

func (j *Journal) Review(id, status, actor string) error {
	if id == "" || actor == "" {
		return errors.New("proposal ID and reviewer required")
	}
	if status != "accepted" && status != "rejected" && status != "superseded" {
		return fmt.Errorf("invalid status %q", status)
	}

	return j.append("review", ReviewEvent{ProposalID: id, Status: status, Actor: actor, At: time.Now().UTC()})
}

// History returns the journal's records in order, each a JSON object with
// its kind and data. A file journal that does not exist yet returns an
// os.ErrNotExist error; a database journal with no records returns none.
func (j *Journal) History() ([]json.RawMessage, error) {
	if j != nil && j.fixed {
		return j.lines, nil
	}
	if j != nil && j.db != nil {
		return j.historyDB()
	}

	data, err := os.ReadFile(j.Path)
	if err != nil {
		return nil, err
	}

	// only complete lines: a line still being written is read next time
	data = data[:bytes.LastIndexByte(data, '\n')+1]
	var lines []json.RawMessage
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		line := bytes.TrimSpace(data[:i])
		data = data[i+1:]
		if len(line) == 0 {
			continue
		}
		if !json.Valid(line) {
			return nil, errors.New("malformed journal entry")
		}
		lines = append(lines, append([]byte(nil), line...))
	}
	return lines, nil
}

// historyDB reads the records appended since the last read and returns
// every record so far.
func (j *Journal) historyDB() ([]json.RawMessage, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	recs, err := j.db.Read(j.seq)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		data := r.Data
		if len(data) == 0 {
			data = json.RawMessage("{}")
		}
		line, err := json.Marshal(struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}{r.Kind, data})
		if err != nil {
			return nil, err
		}
		j.lines = append(j.lines, line)
		j.seq = r.Seq
	}
	return j.lines[:len(j.lines):len(j.lines)], nil
}

// TriageEvent is a human-review candidate, not a trusted OAM relation.
// It contains only stable identifiers and verified evidence references.
type TriageEvent struct {
	SubjectID      string    `json:"subject_id"`
	ObjectID       string    `json:"object_id"`
	EvidenceIDs    []string  `json:"evidence_ids"`
	SourceIDs      []string  `json:"source_ids"`
	ModelID        string    `json:"model_id"`
	FeatureVersion string    `json:"feature_version"`
	At             time.Time `json:"at"`
}

// RecordTriage records a classifier's review decision without creating a
// proposal. It must not be interpreted as acceptance of an OAM relationship.
// The event needs two distinct assets, at least two sources and the model
// that decided; At is set when empty.
func (j *Journal) RecordTriage(e TriageEvent) error {
	if e.SubjectID == "" || e.ObjectID == "" || e.SubjectID == e.ObjectID || len(e.SourceIDs) < 2 ||
		e.ModelID == "" {
		return errors.New("invalid review-only triage event")
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}

	return j.append("triage", e)
}
