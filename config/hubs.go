// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import "fmt"

// HubsOption is the options object holding how hub limits are set:
// options.hubs.derive, set to false, keeps every shared-value signal at its
// fixed limit in signals.json instead of the limit the database's own data
// derives.
const HubsOption = "hubs"

// DerivesHubs reports whether hub limits may come from the database's data:
// true unless options.hubs.derive is false.
func (c *Config) DerivesHubs() bool {
	if c == nil || c.Options == nil {
		return true
	}
	hubs, _ := c.Options[HubsOption].(map[string]interface{})
	v, ok := hubs["derive"].(bool)
	return !ok || v
}

// loadHubSettings checks options.hubs: an object whose derive is true or
// false.
func (c *Config) loadHubSettings(cfg *Config) error {
	raw, ok := c.Options[HubsOption]
	if !ok {
		return nil
	}
	hubs, ok := raw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("%s must be an object, such as {derive: false}", HubsOption)
	}
	for k, v := range hubs {
		if _, ok := v.(bool); k != "derive" || !ok {
			return fmt.Errorf("%s accepts only derive, true or false", HubsOption)
		}
	}
	return nil
}
