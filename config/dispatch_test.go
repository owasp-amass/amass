// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestPhasedDispatch(t *testing.T) {
	var none *Config
	c := &Config{Options: map[string]interface{}{}}
	if none.PhasedDispatch() || c.PhasedDispatch() || c.loadDispatchSettings(c) != nil {
		t.Fatal("the position pipelines are not the default")
	}

	c.Options[DispatchOption] = "Phased"
	if !c.PhasedDispatch() || c.loadDispatchSettings(c) != nil {
		t.Error("phased was not accepted")
	}
	c.Options[DispatchOption] = "positions"
	if c.PhasedDispatch() || c.loadDispatchSettings(c) != nil {
		t.Error("positions was not accepted")
	}
	for _, bad := range []interface{}{"fast", true, 3} {
		c.Options[DispatchOption] = bad
		if c.loadDispatchSettings(c) == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}
