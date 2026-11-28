// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"
)

// AIAttribution returns the attribution mode and journal path for c, with
// the AMASS_ATTRIBUTION and AMASS_REVIEW_JOURNAL environment overrides.
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
		journal = filepath.Join(OutputDirectory(c.Dir), "review.jsonl")
	}

	return mode, journal, nil
}

// AnnounceAIDecisions reports whether the classifier's applied decisions and new
// proposals should be announced proactively. The default is on whenever
// attribution is not off; AISettings.AnnounceDecisions (or
// AMASS_AI_ANNOUNCE_DECISIONS) set to false silences the announcements without
// changing whether the classifier acts.
func (c *Config) AnnounceAIDecisions(lookup func(string) (string, bool)) bool {
	mode, _, err := c.AIAttribution(lookup)
	if err != nil || mode == AttributionOff {
		return false
	}

	base := AISettings{}
	if c.AI != nil {
		base = *c.AI
	}
	s, err := ResolveAISettings(base, lookup)
	if err != nil {
		return false
	}
	if s.AnnounceDecisions != nil {
		return *s.AnnounceDecisions
	}
	return true
}

// AIAttributionCanaryEvery is how many attribution passes go by between
// checks of the passes' lasting cache (AISettings.AttributionCanaryEvery,
// or AMASS_ATTRIBUTION_CANARY_EVERY); zero, and settings that do not
// resolve, never check.
func (c *Config) AIAttributionCanaryEvery(lookup func(string) (string, bool)) int {
	var base AISettings
	if c.AI != nil {
		base = *c.AI
	}

	s, err := ResolveAISettings(base, lookup)
	if err != nil {
		return 0
	}

	return s.AttributionCanaryEvery
}
