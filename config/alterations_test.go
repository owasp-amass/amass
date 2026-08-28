// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"testing"
)

// The engine unmarshals into a fresh Config, so an untagged field arrives zeroed
// and every generator gated on it goes quiet.
func TestAlterationKnobsSurviveTheEngineHandoff(t *testing.T) {
	cli := NewConfig()
	cli.Alterations = true
	cli.FlipWords = false
	cli.FlipNumbers = false
	cli.AddWords = true
	cli.AddNumbers = true
	cli.EditDistance = 0
	cli.MinForWordFlip = 3
	cli.AltWordlist = []string{"dev", "staging"}

	raw, err := json.Marshal(cli)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var engine Config
	if err := json.Unmarshal(raw, &engine); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if !engine.Alterations {
		t.Error("Alterations did not survive the handoff")
	}
	if engine.FlipWords || engine.FlipNumbers {
		t.Errorf("flip generators should be off: flipWords=%v flipNumbers=%v", engine.FlipWords, engine.FlipNumbers)
	}
	if !engine.AddWords || !engine.AddNumbers {
		t.Errorf("add generators did not survive: addWords=%v addNumbers=%v", engine.AddWords, engine.AddNumbers)
	}
	if engine.EditDistance != 0 {
		t.Errorf("EditDistance = %d, want 0", engine.EditDistance)
	}
	if engine.MinForWordFlip != 3 {
		t.Errorf("MinForWordFlip = %d, want 3", engine.MinForWordFlip)
	}
	if len(engine.AltWordlist) != 2 {
		t.Errorf("AltWordlist = %v, want 2 entries", engine.AltWordlist)
	}
}

// The same handoff with the NewConfig defaults, which is the common case.
func TestAlterationDefaultsSurviveTheEngineHandoff(t *testing.T) {
	cli := NewConfig()
	cli.Alterations = true

	raw, err := json.Marshal(cli)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var engine Config
	if err := json.Unmarshal(raw, &engine); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if !engine.FlipWords || !engine.FlipNumbers || !engine.AddWords || !engine.AddNumbers {
		t.Errorf("generator defaults did not survive: flipWords=%v flipNumbers=%v addWords=%v addNumbers=%v",
			engine.FlipWords, engine.FlipNumbers, engine.AddWords, engine.AddNumbers)
	}
	if engine.EditDistance != 1 {
		t.Errorf("EditDistance = %d, want 1", engine.EditDistance)
	}
}
