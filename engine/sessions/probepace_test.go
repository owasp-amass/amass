// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/config"
)

func TestProbePacerDefaults(t *testing.T) {
	cfg := config.NewConfig()

	p := probePacer(cfg)
	if p == nil {
		t.Fatal("the default configuration should pace probes")
	}

	// The default spacing holds a second probe to one host for a while.
	_ = p.Pace(context.Background(), "192.0.2.1")
	start := time.Now()
	_ = p.Pace(context.Background(), "192.0.2.1")
	if time.Since(start) < 400*time.Millisecond {
		t.Errorf("the default pace did not space a host's probes: %v", time.Since(start))
	}
}

func TestProbePacerOptionsOverride(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Options["probe_pace_ms"] = 0

	if probePacer(cfg) != nil {
		t.Error("a probe_pace_ms of 0 should turn pacing off")
	}

	cfg.Options["probe_pace_ms"] = 10
	cfg.Options["probe_jitter_ms"] = 0
	p := probePacer(cfg)
	if p == nil {
		t.Fatal("a positive probe_pace_ms should pace probes")
	}

	_ = p.Pace(context.Background(), "192.0.2.1")
	start := time.Now()
	_ = p.Pace(context.Background(), "192.0.2.1")
	elapsed := time.Since(start)
	if elapsed < 8*time.Millisecond || elapsed > 300*time.Millisecond {
		t.Errorf("a 10ms pace spaced probes by %v", elapsed)
	}
}

func TestOptionMS(t *testing.T) {
	cfg := config.NewConfig()
	if got := optionMS(cfg, "missing", 7); got != 7 {
		t.Errorf("a missing option should fall back: got %d", got)
	}

	cfg.Options["as_float"] = float64(250) // numbers from YAML arrive as float64
	if got := optionMS(cfg, "as_float", 7); got != 250 {
		t.Errorf("a float option read as %d", got)
	}

	cfg.Options["negative"] = -1
	if got := optionMS(cfg, "negative", 7); got != 7 {
		t.Errorf("a negative option should fall back: got %d", got)
	}

	cfg.Options["text"] = "nope"
	if got := optionMS(cfg, "text", 7); got != 7 {
		t.Errorf("a non-numeric option should fall back: got %d", got)
	}
}
