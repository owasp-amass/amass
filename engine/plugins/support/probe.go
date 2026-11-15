// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"math/rand"

	et "github.com/owasp-amass/amass/v5/engine/types"
)

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
