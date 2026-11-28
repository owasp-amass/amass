// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
)

// DispatchOption is the option that chooses how the engine runs an asset's
// handlers: "positions" (the default) passes each event through every
// handler position in order; "phased" runs the resolve positions in order,
// then gives the event to every plugin of each later phase at once.
const DispatchOption = "dispatch"

// The values options.dispatch accepts.
const (
	DispatchPositions = "positions"
	DispatchPhased    = "phased"
)

// PhasedDispatch reports whether options.dispatch is "phased".
func (c *Config) PhasedDispatch() bool {
	if c == nil || c.Options == nil {
		return false
	}
	v, _ := c.Options[DispatchOption].(string)
	return strings.EqualFold(strings.TrimSpace(v), DispatchPhased)
}

// loadDispatchSettings checks options.dispatch: positions or phased.
func (c *Config) loadDispatchSettings(cfg *Config) error {
	raw, ok := c.Options[DispatchOption]
	if !ok {
		return nil
	}
	v, _ := raw.(string)
	switch strings.ToLower(strings.TrimSpace(v)) {
	case DispatchPositions, DispatchPhased:
		return nil
	}
	return fmt.Errorf("%s must be %q or %q", DispatchOption, DispatchPositions, DispatchPhased)
}
