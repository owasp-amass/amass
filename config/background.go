// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
	"time"
)

// DefaultBackgroundHold is how long a run keeps working on background
// collection once its other work is done, when options.background_hold is
// not set.
const DefaultBackgroundHold = 20 * time.Minute

// MaxBackgroundHold is the longest options.background_hold accepted.
const MaxBackgroundHold = 24 * time.Hour

// loadBackgroundSettings reads options.background_hold: how long a run keeps
// working on background collection, such as the web archives' slow queries,
// once its other work is done. Zero does none then: what is still queued is
// left for the next run.
func (c *Config) loadBackgroundSettings(cfg *Config) error {
	raw, ok := c.Options["background_hold"]
	if !ok {
		return nil
	}

	if n, ok := raw.(int); ok && n == 0 {
		// YAML reads a bare 0 as a number
		raw = "0"
	}
	s, ok := raw.(string)
	if !ok {
		return fmt.Errorf("failed to parse the background_hold setting, value is not a duration such as \"20m\"")
	}
	s = strings.TrimSpace(s)
	if s == "0" {
		s = "0s"
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 || d > MaxBackgroundHold {
		return fmt.Errorf("background_hold %q must be a duration from 0 to %s", s, MaxBackgroundHold)
	}

	c.BackgroundHold = &d
	return nil
}

// BackgroundHoldDuration returns options.background_hold, or
// DefaultBackgroundHold when it is not set.
func (c *Config) BackgroundHoldDuration() time.Duration {
	if c == nil || c.BackgroundHold == nil {
		return DefaultBackgroundHold
	}
	return *c.BackgroundHold
}
