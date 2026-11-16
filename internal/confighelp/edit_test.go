// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package confighelp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProposedEditValidate(t *testing.T) {
	valid := ProposedEdit{Content: "seed:\n  domains:\n    - owasp.org\nscope:\n  ports:\n    - 443\n"}
	if err := valid.Validate(); err != nil {
		t.Errorf("a valid configuration was rejected: %v", err)
	}

	if err := (ProposedEdit{Content: ""}).Validate(); err == nil {
		t.Error("an empty configuration was accepted")
	}
	if err := (ProposedEdit{Content: "scope: [unterminated\n"}).Validate(); err == nil {
		t.Error("malformed YAML was accepted")
	}
}

func TestProposedEditApplyNewFile(t *testing.T) {
	// Building a brand-new configuration: Apply writes a path that does not
	// exist yet.
	path := filepath.Join(t.TempDir(), "new", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}

	edit := ProposedEdit{Summary: "new config", Content: "seed:\n  domains:\n    - example.com\n"}
	if err := edit.Apply(path); err != nil {
		t.Fatalf("applying a new config failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil || string(got) != edit.Content {
		t.Errorf("the new config was not written as proposed: %q, %v", string(got), err)
	}
}

func TestProposedEditApplyKeepsMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("scope:\n  ports:\n    - 80\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	edit := ProposedEdit{Content: "scope:\n  ports:\n    - 443\n"}
	if err := edit.Apply(path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Errorf("the file mode was not preserved: %v, %v", info.Mode().Perm(), err)
	}

	// An invalid proposal must not reach disk.
	if err := (ProposedEdit{Content: "scope: [bad\n"}).Apply(path); err == nil {
		t.Error("an invalid proposal was applied")
	}
	if got, _ := os.ReadFile(path); !strings.Contains(string(got), "443") {
		t.Error("the file was overwritten by an invalid proposal")
	}
}

func TestDiff(t *testing.T) {
	d := Diff("a\nb\nc\n", "a\nx\nc\n")
	if !strings.Contains(d, "- b") || !strings.Contains(d, "+ x") || !strings.Contains(d, "  a") {
		t.Errorf("unexpected diff:\n%s", d)
	}
}
