// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"testing"
)

// The engine receives a session's configuration as the JSON the client
// marshals, so a setting with no JSON tag never reaches the engine. This
// guards the settings the engine and its plugins read: they must survive a
// marshal/unmarshal round trip, the same path CreateSession takes.
func TestConfigReachesTheEngineOverJSON(t *testing.T) {
	c := NewConfig()
	c.Scope.Domains = []string{"example.com"}
	c.Active = true
	c.BruteForcing = true
	c.MaxDepth = 3
	c.Recursive = true
	c.MinForRecursive = 2
	c.Alterations = true
	c.FlipWords = true
	c.FlipNumbers = true
	c.AddWords = true
	c.AddNumbers = true
	c.EditDistance = 2
	c.RecordTypes = []string{"A", "AAAA", "CNAME"}
	c.ProvidedNames = []string{"known.example.com"}
	c.Mode = "active"
	c.MinimumTTL = 720
	c.Options["probe_pace_ms"] = 250
	c.Options["probe_jitter_ms"] = 750

	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("the configuration did not marshal: %v", err)
	}

	var got Config
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("the configuration did not unmarshal: %v", err)
	}

	if !got.Active || !got.BruteForcing || !got.Alterations {
		t.Errorf("mode flags were lost: active=%v brute=%v alts=%v", got.Active, got.BruteForcing, got.Alterations)
	}
	if got.MaxDepth != 3 || !got.Recursive || got.MinForRecursive != 2 {
		t.Errorf("recursion settings were lost: depth=%d recursive=%v min=%d",
			got.MaxDepth, got.Recursive, got.MinForRecursive)
	}
	if !got.FlipWords || !got.FlipNumbers || !got.AddWords || !got.AddNumbers || got.EditDistance != 2 {
		t.Errorf("name-alteration settings were lost: flip_words=%v flip_numbers=%v add_words=%v add_numbers=%v edit_distance=%d",
			got.FlipWords, got.FlipNumbers, got.AddWords, got.AddNumbers, got.EditDistance)
	}
	if len(got.RecordTypes) != 3 {
		t.Errorf("record types were lost: %v", got.RecordTypes)
	}
	if len(got.ProvidedNames) != 1 || got.ProvidedNames[0] != "known.example.com" {
		t.Errorf("provided names were lost: %v", got.ProvidedNames)
	}
	if got.Mode != "active" || got.MinimumTTL != 720 {
		t.Errorf("mode or TTL were lost: mode=%q ttl=%d", got.Mode, got.MinimumTTL)
	}

	// Options carry behavioral knobs such as the probe pacing; numbers return
	// as float64 after a JSON round trip, which the readers expect.
	if got.Options == nil {
		t.Fatal("the options map was lost")
	}
	if v, ok := got.Options["probe_pace_ms"].(float64); !ok || v != 250 {
		t.Errorf("a probe pacing option was lost: %v", got.Options["probe_pace_ms"])
	}
}
