// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package coord is how the tools sharing one Asset Database coordinate
// through it: the topics of the database's journal (an append-only log),
// and later its leases. A topic holds records of kinds the tool defines,
// each about a key; the database orders them across every writer.
package coord

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
)

// Store is the Asset Database's journal (asset-db repository.JournalStore).
type Store interface {
	AppendJournal(ctx context.Context, rec *dbt.JournalRecord) (*dbt.JournalRecord, error)
	ReadJournal(ctx context.Context, topic string, after int64, limit int) ([]*dbt.JournalRecord, error)
	ReadJournalFiltered(ctx context.Context, topic string, f dbt.JournalFilter, after int64,
		limit int) ([]*dbt.JournalRecord, error)
}

// timeout bounds one read or write of a topic.
const timeout = time.Minute

// Topic is one topic of the database's journal.
type Topic struct {
	Store Store
	Name  string
}

// Open is the topic of repo's journal, or nil when the database keeps no
// journal (asset-db keeps one in PostgreSQL and SQLite).
func Open(repo repository.Repository, name string) *Topic {
	if s, ok := repo.(Store); ok && s != nil && name != "" {
		return &Topic{Store: s, Name: name}
	}
	return nil
}

// Append appends a record of kind about key, with data marshaled as JSON
// (a json.RawMessage is kept as it is), and returns it with its sequence
// number.
func (t *Topic) Append(kind, key string, data any) (*dbt.JournalRecord, error) {
	if t == nil || t.Store == nil {
		return nil, errors.New("no journal topic")
	}
	raw, ok := data.(json.RawMessage)
	if !ok {
		var err error
		if raw, err = json.Marshal(data); err != nil {
			return nil, err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return t.Store.AppendJournal(ctx, &dbt.JournalRecord{Topic: t.Name, Kind: kind, Key: key, Data: raw,
		Actor: Actor()})
}

// Read returns the topic's records after the sequence number after (all
// when 0), in order.
func (t *Topic) Read(after int64) ([]*dbt.JournalRecord, error) {
	if t == nil || t.Store == nil {
		return nil, errors.New("no journal topic")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return t.Store.ReadJournal(ctx, t.Name, after, 0)
}

// ReadWhere returns the topic's records after the sequence number after
// (all when 0) that the filter lets through, in order: those about its key,
// when it has one, and of its kinds, when it has any.
func (t *Topic) ReadWhere(f dbt.JournalFilter, after int64) ([]*dbt.JournalRecord, error) {
	if t == nil || t.Store == nil {
		return nil, errors.New("no journal topic")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return t.Store.ReadJournalFiltered(ctx, t.Name, f, after, 0)
}

// Actor names this process for the records it writes.
func Actor() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return "amass@" + host
}
