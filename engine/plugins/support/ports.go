// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"slices"
	"sync"

	"github.com/owasp-amass/amass/v5/config"
)

// The configuration's scope.ports lists every port active enumeration may
// probe. Each probe speaks its own protocols: a probe that knows the
// protocol on a port claims it, so the HTTP probes leave it alone, and a
// probe tries only the ports it knows that scope.ports also lists.
var (
	claimMu sync.RWMutex
	claimed = map[int]string{}
)

// ClaimPorts records that a probe speaks the protocol usually on ports.
func ClaimPorts(probe string, ports ...int) {
	claimMu.Lock()
	defer claimMu.Unlock()
	for _, p := range ports {
		claimed[p] = probe
	}
}

// ClaimedPort reports whether a probe other than HTTP claims a port.
func ClaimedPort(port int) bool {
	claimMu.RLock()
	defer claimMu.RUnlock()
	_, ok := claimed[port]
	return ok
}

// ScopePorts returns the ports a probe knows that scope.ports lists, in the
// probe's order.
func ScopePorts(cfg *config.Config, known []int) []int {
	if cfg == nil || cfg.Scope == nil {
		return nil
	}

	var out []int
	for _, p := range known {
		if slices.Contains(cfg.Scope.Ports, p) {
			out = append(out, p)
		}
	}

	return out
}

// HTTPPorts returns the scope.ports no other probe claims, for the HTTP
// probes.
func HTTPPorts(cfg *config.Config) []int {
	if cfg == nil || cfg.Scope == nil {
		return nil
	}

	var out []int
	for _, p := range cfg.Scope.Ports {
		if !ClaimedPort(p) {
			out = append(out, p)
		}
	}

	return out
}
