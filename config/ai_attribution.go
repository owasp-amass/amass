// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"
)

// AIAttribution returns the attribution mode and journal path for c, with
// the AMASS_AI_ATTRIBUTION and AMASS_AI_JOURNAL environment overrides.
func (c *Config) AIAttribution(lookup func(string) (string, bool)) (string, string, error) {
	var base AISettings
	if c.AI != nil {
		base = *c.AI
	}

	s, err := ResolveAISettings(base, lookup)
	if err != nil {
		return "", "", err
	}

	mode := strings.ToLower(strings.TrimSpace(s.Attribution))
	if mode == "" {
		mode = AttributionAuto
	}

	journal := s.Journal
	if journal == "" {
		journal = filepath.Join(OutputDirectory(c.Dir), "ai-review.jsonl")
	}

	return mode, journal, nil
}
