// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestDerivesHubs(t *testing.T) {
	var none *Config
	c := &Config{Options: map[string]interface{}{}}
	if !none.DerivesHubs() || !c.DerivesHubs() || c.loadHubSettings(c) != nil {
		t.Fatal("deriving is not the default")
	}
	c.Options[HubsOption] = map[string]interface{}{"derive": false}
	if c.DerivesHubs() || c.loadHubSettings(c) != nil {
		t.Error("derive: false did not fix the limits")
	}
	for _, bad := range []interface{}{"no", map[string]interface{}{"derive": "no"},
		map[string]interface{}{"limit": 5}} {
		c.Options[HubsOption] = bad
		if c.loadHubSettings(c) == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}
