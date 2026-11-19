// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"math/rand"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

// defaultProbeTimeoutMS is the dial timeout, in milliseconds, used for active
// enumeration probes when the configuration does not set one.
const defaultProbeTimeoutMS = 2000

// ProbeDialTimeout returns the longest an active-enumeration probe waits to
// establish a TCP connection to a host's port. A filtered or dead port waits
// out this whole duration before the next port on the host is tried, and ports
// are probed one at a time per host, so this is the dominant lever on how long
// an active enumeration takes against unresponsive hosts. The configuration
// option "probe_timeout_ms" overrides the 2000ms (2s) default; a value of zero
// or less yields the default, since a zero dial timeout would fail every probe.
func ProbeDialTimeout(cfg *config.Config) time.Duration {
	ms := defaultProbeTimeoutMS
	if cfg != nil && cfg.Options != nil {
		switch v := cfg.Options["probe_timeout_ms"].(type) {
		case int:
			if v > 0 {
				ms = v
			}
		case int64:
			if v > 0 {
				ms = int(v)
			}
		case float64:
			if v > 0 {
				ms = int(v)
			}
		}
	}

	return time.Duration(ms) * time.Millisecond
}

// PaceProbe holds an active-enumeration probe until the session's pacer
// allows another connection to host, so that one host is not reached by a
// burst of probes to many ports at once. It returns the session context's
// error if the session ends while waiting, and nothing when no pacer is
// configured. host is the address being probed, without a port.
func PaceProbe(e *et.Event, host string) error {
	if e == nil || e.Session == nil {
		return nil
	}

	return et.ProbePacerFrom(e.Session.Ctx()).Pace(e.Session.Ctx(), host)
}

// ShufflePorts returns ports in a random order, so a host's probes do not
// arrive in a fixed, recognizable sequence. The input is not modified.
func ShufflePorts(ports []int) []int {
	out := make([]int, len(ports))
	copy(out, ports)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}
