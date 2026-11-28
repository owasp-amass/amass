// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package secrets

import "testing"

// A found credential is sealed, opened only under its key, kept apart from
// data source credentials, and rotated with them.
func TestFoundCredentials(t *testing.T) {
	s := &Store{DB: &FakeDB{}, Key: newKey(t)}
	if err := s.Put("Shodan", "apikey", "source-key", "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFound("github_token", "abc123", "found-value", "Exposed-Secrets"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFound("bad:kind", "abc123", "v", "x"); err == nil {
		t.Error("a kind with a colon was accepted")
	}

	if v, err := s.Found("github_token", "abc123", "test"); err != nil || v != "found-value" {
		t.Fatalf("Found = %q, %v", v, err)
	}
	values, skipped, err := s.Values()
	if err != nil || skipped != 0 || len(values) != 1 || values["Shodan"]["apikey"] != "source-key" {
		t.Errorf("data source values = %v, skipped %d, %v", values, skipped, err)
	}
	if entries, _ := s.List(); len(entries) != 1 {
		t.Errorf("entries = %v", entries)
	}

	next := newKey(t)
	if rotated, skipped, err := s.Rotate(next, "test"); err != nil || rotated != 2 || skipped != 0 {
		t.Fatalf("Rotate = %d, %d, %v", rotated, skipped, err)
	}
	if _, err := s.Found("github_token", "abc123", "test"); err == nil {
		t.Error("the old key still opens the rotated credential")
	}
	moved := &Store{DB: s.DB, Key: next}
	if v, err := moved.Found("github_token", "abc123", "test"); err != nil || v != "found-value" {
		t.Errorf("after rotation Found = %q, %v", v, err)
	}
}

func TestParseFound(t *testing.T) {
	for ref, want := range map[string]string{"github_token:abc": "github_token abc",
		"exposed_secret:slack_token:def": "slack_token def", "nohash": "", "a:b:c": ""} {
		kind, hash, ok := ParseFound(ref)
		got := ""
		if ok {
			got = kind + " " + hash
		}
		if got != want {
			t.Errorf("ParseFound(%q) = %q, want %q", ref, got, want)
		}
	}
}
