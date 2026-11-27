// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateSignalIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "review.jsonl")
	before := `{"kind":"ownership_proposal","data":{"id":"p1","signal_ids":["email_auth_reference","shared-registrant-org"],"evidence":["a <b> & c"]}}
{"kind":"gap","data":{"signals":[{"signal":"same_favicon","weight":0.15}]}}
{"kind":"scope_expansion","data":{"signal_ids":["shared-registrant-org"]}}
not a record
`
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}

	j := &Journal{Path: path}
	n, err := j.MigrateSignalIDs()
	if err != nil || n != 2 {
		t.Fatalf("MigrateSignalIDs = %d, %v; want 2 records", n, err)
	}
	after, _ := os.ReadFile(path)
	got := string(after)
	for _, want := range []string{`"spf-authorizes"`, `"shared-favicon"`, `"weight":0.15`, `a <b> & c`,
		`{"kind":"scope_expansion","data":{"signal_ids":["shared-registrant-org"]}}`, "not a record\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("migrated journal lacks %s:\n%s", want, got)
		}
	}
	for _, old := range []string{"email_auth_reference", "same_favicon"} {
		if strings.Contains(got, old) {
			t.Errorf("migrated journal still names %s", old)
		}
	}

	backups, _ := filepath.Glob(path + ".bak-*")
	if len(backups) != 1 {
		t.Fatalf("backups = %v", backups)
	}
	if kept, _ := os.ReadFile(backups[0]); string(kept) != before {
		t.Error("the backup is not the journal as it was")
	}

	// A second run finds nothing to change and writes nothing.
	if n, err := j.MigrateSignalIDs(); err != nil || n != 0 {
		t.Errorf("second run = %d, %v", n, err)
	}
	if backups, _ := filepath.Glob(path + ".bak-*"); len(backups) != 1 {
		t.Errorf("a second run wrote a backup: %v", backups)
	}
}
