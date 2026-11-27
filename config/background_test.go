// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
	"time"
)

func TestBackgroundHold(t *testing.T) {
	if got := NewConfig().BackgroundHoldDuration(); got != DefaultBackgroundHold {
		t.Errorf("unset: %s", got)
	}
	for raw, want := range map[any]time.Duration{"0": 0, 0: 0, "45m": 45 * time.Minute, " 2h ": 2 * time.Hour} {
		c := NewConfig()
		c.Options = map[string]interface{}{"background_hold": raw}
		if err := c.loadBackgroundSettings(c); err != nil {
			t.Fatalf("%v: %v", raw, err)
		}
		if got := c.BackgroundHoldDuration(); got != want {
			t.Errorf("%v: %s, want %s", raw, got, want)
		}
	}
	for _, raw := range []any{"-1m", "48h", "soon", 20} {
		c := NewConfig()
		c.Options = map[string]interface{}{"background_hold": raw}
		if err := c.loadBackgroundSettings(c); err == nil {
			t.Errorf("%v was accepted", raw)
		}
	}
}
