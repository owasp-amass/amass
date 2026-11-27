// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package confighelp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/owasp-amass/amass/v5/config"
)

// ProposedEdit is a complete replacement of a configuration file that the
// assistant suggests. Keeping the whole document, rather than a fragment,
// lets the change be validated with the real configuration parser and shown
// to the user in full before it is applied.
type ProposedEdit struct {
	// Summary is a one-line description of what the change does.
	Summary string `json:"summary"`
	// Rationale explains the change and its trade-offs.
	Rationale string `json:"rationale"`
	// Content is the proposed configuration file in full.
	Content string `json:"content"`
}

// Validate checks that a proposed configuration parses and is accepted by
// the real Amass configuration loader, so a suggested change can never be a
// configuration Amass would reject. It returns the loader's error verbatim.
func (e ProposedEdit) Validate() error {
	_, err := e.load()
	return err
}

// Warnings returns what a valid configuration should be told about, such as
// setting no expansion policy. An invalid one has none.
func (e ProposedEdit) Warnings() []string {
	cfg, err := e.load()
	if err != nil || cfg.HasExpansionPolicy() {
		return nil
	}
	return []string{config.NoPolicyWarning}
}

// load loads the proposed configuration with the real loader.
func (e ProposedEdit) load() (*config.Config, error) {
	if strings.TrimSpace(e.Content) == "" {
		return nil, errors.New("the proposed configuration is empty")
	}

	dir, err := os.MkdirTemp("", "amass-confighelp")
	if err != nil {
		return nil, err
	}

	defer func() { _ = os.RemoveAll(dir) }()

	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(e.Content), 0o600); err != nil {
		return nil, err
	}

	cfg := config.NewConfig()
	if err := cfg.LoadSettings(path); err != nil {
		return nil, fmt.Errorf("the proposed configuration is not valid: %w", err)
	}

	return cfg, cfg.CheckSettings()
}

// Apply writes the proposed configuration to path. The caller is
// responsible for obtaining the user's approval first; Apply itself only
// writes. It refuses an invalid proposal so a bad change cannot reach disk.
func (e ProposedEdit) Apply(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("no configuration file path was given")
	}
	if err := e.Validate(); err != nil {
		return err
	}

	perm := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}

	return os.WriteFile(path, []byte(e.Content), perm)
}

// Diff returns a readable line-by-line comparison of the current and
// proposed configurations: lines only in the current marked "-", lines only
// in the proposed marked "+", in the order they appear. It is for the user
// to review a change, not a machine patch.
func Diff(current, proposed string) string {
	cur := strings.Split(strings.TrimRight(current, "\n"), "\n")
	prop := strings.Split(strings.TrimRight(proposed, "\n"), "\n")

	// The longest common subsequence of lines keeps unchanged lines aligned.
	n, m := len(cur), len(prop)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if cur[i] == prop[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	var b strings.Builder
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case cur[i] == prop[j]:
			fmt.Fprintf(&b, "  %s\n", cur[i])
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			fmt.Fprintf(&b, "- %s\n", cur[i])
			i++
		default:
			fmt.Fprintf(&b, "+ %s\n", prop[j])
			j++
		}
	}
	for ; i < n; i++ {
		fmt.Fprintf(&b, "- %s\n", cur[i])
	}
	for ; j < m; j++ {
		fmt.Fprintf(&b, "+ %s\n", prop[j])
	}

	return b.String()
}
