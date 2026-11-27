// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

func TestRoutingRegistryCatalog(t *testing.T) {
	c := RoutingRegistryCatalog()
	if c.MaxRoutes <= 0 || c.IRRWhois == "" {
		t.Fatalf("catalog %+v", c)
	}
	if !c.RegistryMaintainer("ripe-ncc-hm-mnt") || !c.RegistryMaintainer("RPKI-MNT") ||
		c.RegistryMaintainer("MAINT-ACME") {
		t.Error("RegistryMaintainer misjudges registry and operator maintainers")
	}
}
