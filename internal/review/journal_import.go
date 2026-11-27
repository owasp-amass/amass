// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
)

// journalImport marks a file journal imported into a shared journal, by the
// hash of its contents.
type journalImport struct {
	SHA256  string `json:"sha256"`
	Path    string `json:"path"`
	Records int    `json:"records"`
}

// FileNotImported reports whether a shared journal's Path names a file
// journal with records that were never imported (ImportJournal): they are
// not read while the journal is kept in the database.
func (j *Journal) FileNotImported() bool {
	if !j.Shared() || j.Path == "" {
		return false
	}
	data, err := os.ReadFile(j.Path)
	if err != nil || len(data) == 0 {
		return false
	}
	sum := sha256.Sum256(data)
	key := hex.EncodeToString(sum[:])

	hist, err := j.History()
	if err != nil {
		return false
	}
	for _, raw := range hist {
		var rec struct {
			Kind string        `json:"kind"`
			Data journalImport `json:"data"`
		}
		if json.Unmarshal(raw, &rec) == nil && rec.Kind == "journal_import" && rec.Data.SHA256 == key {
			return false
		}
	}
	return true
}

// ImportJournal appends the records of the file journal at path to the
// shared journal, in order, and reports how many. A file is imported once:
// a record of the import, keyed by the hash of the file's contents, keeps a
// second import of the same file from appending its records again (done
// reports it was imported before). Run migrate-signals on the file first, as
// a shared journal is never rewritten.
func (j *Journal) ImportJournal(path string) (n int, done bool, err error) {
	if !j.Shared() {
		return 0, false, errors.New("the journal is not kept in the Asset Database")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false, err
	}
	sum := sha256.Sum256(data)
	key := hex.EncodeToString(sum[:])

	hist, err := j.History()
	if err != nil {
		return 0, false, err
	}
	for _, raw := range hist {
		var rec struct {
			Kind string        `json:"kind"`
			Data journalImport `json:"data"`
		}
		if json.Unmarshal(raw, &rec) == nil && rec.Kind == "journal_import" && rec.Data.SHA256 == key {
			return rec.Data.Records, true, nil
		}
	}

	lines, err := (&Journal{Path: path}).History()
	if err != nil {
		return 0, false, err
	}
	for _, raw := range lines {
		var rec struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &rec); err != nil || rec.Kind == "" {
			return n, false, errors.New("malformed journal record")
		}
		if err := j.append(rec.Kind, rec.Data); err != nil {
			return n, false, err
		}
		n++
	}
	return n, false, j.append("journal_import", journalImport{SHA256: key, Path: path, Records: n})
}
