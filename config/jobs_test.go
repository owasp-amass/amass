// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestJoinsRunningJobs(t *testing.T) {
	var none *Config
	c := &Config{}
	if !none.JoinsRunningJobs() || !c.JoinsRunningJobs() {
		t.Fatal("joining is not the default")
	}
	c.SetJoinRunningJobs(false)
	if c.JoinsRunningJobs() {
		t.Error("the option did not stop joining")
	}
	c.Options[JoinRunningJobsOption] = "yes"
	if !c.JoinsRunningJobs() {
		t.Error("a value that is not false stopped joining")
	}
}

func TestMaxJobWorkers(t *testing.T) {
	var none *Config
	c := &Config{Options: map[string]interface{}{}}
	if none.MaxJobWorkers() != 0 || c.MaxJobWorkers() != 0 || c.loadJobSettings(c) != nil {
		t.Fatal("an unset cap is not 0")
	}

	c.Options[MaxJobWorkersOption] = 3
	if err := c.loadJobSettings(c); err != nil || c.MaxJobWorkers() != 3 {
		t.Errorf("the cap of 3 was not taken: %v", err)
	}
	c.Options[MaxJobWorkersOption] = float64(4)
	if c.MaxJobWorkers() != 4 {
		t.Error("the cap from a job record's JSON was not read")
	}
	for _, bad := range []interface{}{-1, "2", 2.5} {
		c.Options[MaxJobWorkersOption] = bad
		if c.loadJobSettings(c) == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}
