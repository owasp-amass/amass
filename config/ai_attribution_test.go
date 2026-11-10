// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"testing"
)

func TestAIAttributionDefaultsAndOverrides(t *testing.T) {
	c := &Config{Dir: t.TempDir()}
	none := func(string) (string, bool) { return "", false }

	mode, journal, err := c.AIAttribution(none)
	if err != nil || mode != AttributionAuto || journal != filepath.Join(c.Dir, "ai-review.jsonl") {
		t.Errorf("defaults = %q, %q, %v", mode, journal, err)
	}

	c.AI = &AISettings{Attribution: "Journal", Journal: "/data/review.jsonl"}
	if mode, journal, err = c.AIAttribution(none); err != nil || mode != AttributionJournal ||
		journal != "/data/review.jsonl" {
		t.Errorf("YAML settings = %q, %q, %v", mode, journal, err)
	}

	env := map[string]string{"AMASS_AI_ATTRIBUTION": "off", "AMASS_AI_JOURNAL": "/shared/review.jsonl"}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	if mode, journal, err = c.AIAttribution(lookup); err != nil || mode != AttributionOff ||
		journal != "/shared/review.jsonl" {
		t.Errorf("environment overrides = %q, %q, %v", mode, journal, err)
	}

	env["AMASS_AI_ATTRIBUTION"] = "sometimes"
	if _, _, err := c.AIAttribution(lookup); err == nil {
		t.Error("an unknown attribution mode was accepted")
	}
}
