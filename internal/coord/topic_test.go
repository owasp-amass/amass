// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package coord

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
)

// A topic appends records of its own, keyed, and reads those after a
// sequence number; a repository without a journal has no topic.
func TestTopic(t *testing.T) {
	if Open(nil, "runs") != nil {
		t.Error("a missing repository has a topic")
	}

	db := &FakeStore{}
	runs, watches := Open(db, "runs"), Open(db, "watches")
	if runs == nil || watches == nil {
		t.Fatal("a journal store has no topic")
	}

	first, err := runs.Append("run", "r-1", map[string]string{"state": "running"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := watches.Append("watch", "w-1", json.RawMessage(`{"id":"w-1"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := runs.Append("run", "r-1", map[string]string{"state": "finished"}); err != nil {
		t.Fatal(err)
	}

	recs, err := runs.Read(0)
	if err != nil || len(recs) != 2 || recs[0].Key != "r-1" || recs[0].Actor == "" {
		t.Fatalf("runs = %+v, %v", recs, err)
	}
	if recs, err = runs.Read(first.Seq); err != nil || len(recs) != 1 || string(recs[0].Data) != `{"state":"finished"}` {
		t.Fatalf("runs after the first = %+v, %v", recs, err)
	}
	if recs, _ = watches.Read(0); len(recs) != 1 || string(recs[0].Data) != `{"id":"w-1"}` {
		t.Fatalf("watches = %+v", recs)
	}

	// a filtered read: a key's records, and some kinds' records
	if _, err := runs.Append("stop", "r-2", nil); err != nil {
		t.Fatal(err)
	}
	if recs, err = runs.ReadWhere(dbt.JournalFilter{Key: "r-2"}, 0); err != nil || len(recs) != 1 ||
		recs[0].Kind != "stop" {
		t.Errorf("r-2's records = %+v, %v", recs, err)
	}
	if recs, err = runs.ReadWhere(dbt.JournalFilter{Kinds: []string{"run"}}, first.Seq); err != nil ||
		len(recs) != 1 || recs[0].Key != "r-1" {
		t.Errorf("run records after the first = %+v, %v", recs, err)
	}
}

// A lease has one holder; Hold keeps it until released, and a process with
// no leases to share takes every one.
func TestLeases(t *testing.T) {
	store := &FakeLeases{}
	a, b := &Leases{Store: store, Holder: "a"}, &Leases{Store: store, Holder: "b"}

	if !a.Try("watch:1:100", time.Hour) || b.Try("watch:1:100", time.Hour) {
		t.Fatal("a lease had two holders")
	}

	release, ok := a.Hold(context.Background(), "run:r-1", 30*time.Millisecond)
	if !ok {
		t.Fatal("a free lease was not held")
	}
	time.Sleep(60 * time.Millisecond)
	if store.Holder("run:r-1") != "a" {
		t.Error("a held lease was not renewed")
	}
	if _, ok := b.Hold(context.Background(), "run:r-1", time.Minute); ok {
		t.Error("a held lease was taken")
	}
	release()
	if store.Holder("run:r-1") != "" {
		t.Error("a released lease is still held")
	}

	var none *Leases
	if !none.Try("x", time.Minute) {
		t.Error("no leases refused one")
	}
	if OpenLeases(nil) != nil || OpenLeases(store) == nil {
		t.Error("OpenLeases")
	}
}
