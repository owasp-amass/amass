// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import "fmt"

func (c *Config) loadActiveSettings(cfg *Config) error {
	// Retrieve the active option from the configuration
	activeinterface, ok := c.Options["active"]
	if !ok {
		// "active" not found in options, so nothing to do here.
		return nil
	}

	active, ok := activeinterface.(bool)
	if !ok {
		return fmt.Errorf("failed to parse active setting, value is not a boolean")
	}
	c.Active = active
	return nil
}
