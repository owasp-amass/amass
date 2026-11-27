// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ssh_probes

import (
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
)

// A configuration without ports probes every SSH port.
func TestSSHPortsAreDefaults(t *testing.T) {
	for _, p := range sshPorts {
		if !slices.Contains(config.DefaultPorts, p) {
			t.Errorf("SSH port %d is missing from config.DefaultPorts", p)
		}
	}
}
