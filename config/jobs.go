// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import "fmt"

// JoinRunningJobsOption is the option that, set to false, keeps an
// enumeration from joining a running enumeration of its scope that other
// engines on the same database work on.
const JoinRunningJobsOption = "join_running_jobs"

// JoinsRunningJobs reports whether the enumeration may join a running one
// of its scope: true unless JoinRunningJobsOption is false.
func (c *Config) JoinsRunningJobs() bool {
	if c == nil || c.Options == nil {
		return true
	}
	v, ok := c.Options[JoinRunningJobsOption].(bool)
	return !ok || v
}

// SetJoinRunningJobs sets JoinRunningJobsOption.
func (c *Config) SetJoinRunningJobs(join bool) {
	if c.Options == nil {
		c.Options = make(map[string]interface{})
	}
	c.Options[JoinRunningJobsOption] = join
}

// MaxJobWorkersOption caps the live workers of an enumeration started with
// this configuration, a job that engines on one database share: a pool
// engine does not join a job that already has this many. An engine asked to
// collect the job's scope still joins it. 0, the default, sets no cap. The
// job keeps the value its first session started with.
const MaxJobWorkersOption = "max_job_workers"

// MaxJobWorkers returns MaxJobWorkersOption, or 0 (no cap) when it is not
// set.
func (c *Config) MaxJobWorkers() int {
	if c == nil || c.Options == nil {
		return 0
	}
	switch v := c.Options[MaxJobWorkersOption].(type) {
	case int:
		return max(0, v)
	case float64:
		// a job record keeps its configuration as JSON
		return max(0, int(v))
	}
	return 0
}

// loadJobSettings checks MaxJobWorkersOption: a whole number, 0 or more.
func (c *Config) loadJobSettings(cfg *Config) error {
	raw, ok := c.Options[MaxJobWorkersOption]
	if !ok {
		return nil
	}
	if n, ok := raw.(int); !ok || n < 0 {
		return fmt.Errorf("%s must be a whole number: 0 for no cap, or the most engines that may work on one "+
			"enumeration at once", MaxJobWorkersOption)
	}
	return nil
}
