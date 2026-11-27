// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
)

// loadNetworkSettings reads options.interface, the network interface the
// enumeration's traffic leaves through, and options.active_route and
// options.active_udp_route, the route its active traffic takes. The engine
// checks them, since the interfaces and the proxy are reached from its host.
func (c *Config) loadNetworkSettings(cfg *Config) error {
	for key, dst := range map[string]*string{
		"interface":        &c.Interface,
		"active_route":     &c.ActiveRoute,
		"active_udp_route": &c.ActiveUDPRoute,
	} {
		raw, ok := c.Options[key]
		if !ok {
			continue
		}

		v, ok := raw.(string)
		if !ok {
			return fmt.Errorf("failed to parse the %s setting, value is not a string", key)
		}
		*dst = strings.TrimSpace(v)
	}
	return nil
}
