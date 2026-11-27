// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"fmt"
	"sync"
	"testing"
)

func TestMetaMapEntries(t *testing.T) {
	mm := newMetaMap()
	if err := mm.InsertEntry("", "e1", 1); err == nil {
		t.Error("an entry without a session was accepted")
	}
	if err := mm.InsertEntry("s1", "", 1); err == nil {
		t.Error("an entry without an entity was accepted")
	}
	if _, err := mm.GetEntry("s1", "e1"); err == nil {
		t.Error("an unknown session returned an entry")
	}

	_ = mm.InsertEntry("s1", "e1", "first")
	_ = mm.InsertEntry("s1", "e1", "second")
	_ = mm.InsertEntry("s2", "e1", "other session")
	if v, err := mm.GetEntry("s1", "e1"); err != nil || v != "second" {
		t.Errorf("GetEntry = %v, %v; want the latest value", v, err)
	}
	if v, err := mm.GetEntry("s2", "e1"); err != nil || v != "other session" {
		t.Errorf("sessions share entries: %v, %v", v, err)
	}
	if _, err := mm.GetEntry("s1", "e2"); err == nil {
		t.Error("an unknown entity returned an entry")
	}

	if err := mm.DeleteSessionEntry("s1", "e1"); err != nil {
		t.Fatal(err)
	}
	if _, err := mm.GetEntry("s1", "e1"); err == nil {
		t.Error("a deleted entry is still returned")
	}
	if err := mm.DeleteSessionEntry("s9", "e1"); err == nil {
		t.Error("deleting from an unknown session succeeded")
	}

	_ = mm.DeleteSession("s2")
	if _, err := mm.GetEntry("s2", "e1"); err == nil {
		t.Error("a deleted session's entries are still returned")
	}
}

func TestMetaMapRemoveInactiveSessions(t *testing.T) {
	mm := newMetaMap()
	for _, sid := range []string{"a", "b", "c"} {
		_ = mm.InsertEntry(sid, "e", sid)
	}

	mm.RemoveInactiveSessions([]string{"b", "z"})
	for sid, want := range map[string]bool{"a": false, "b": true, "c": false} {
		if _, err := mm.GetEntry(sid, "e"); (err == nil) != want {
			t.Errorf("session %s kept = %v, want %v", sid, err == nil, want)
		}
	}

	// No active sessions removes them all.
	mm.RemoveInactiveSessions(nil)
	if _, err := mm.GetEntry("b", "e"); err == nil {
		t.Error("an inactive session survived")
	}
}

func TestMetaMapConcurrentUse(t *testing.T) {
	mm := newMetaMap()

	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			sid := fmt.Sprintf("s%d", w%2)
			for i := range 200 {
				eid := fmt.Sprintf("e%d", i)
				_ = mm.InsertEntry(sid, eid, i)
				_, _ = mm.GetEntry(sid, eid)
				if i%10 == 0 {
					_ = mm.DeleteSessionEntry(sid, eid)
				}
				if i%50 == 0 {
					mm.RemoveInactiveSessions([]string{"s0", "s1"})
				}
			}
		}()
	}

	wg.Wait()
	if v, err := mm.GetEntry("s0", "e199"); err != nil || v != 199 {
		t.Errorf("after concurrent use: %v, %v", v, err)
	}
}
