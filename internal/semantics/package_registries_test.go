// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

func TestPackageRegistryCatalog(t *testing.T) {
	c := PackageRegistryCatalog()
	if c.MaxPackages <= 0 || c.Maven.Search == "" || c.NPM.Search == "" {
		t.Fatalf("catalog = %+v", c)
	}
	for host, want := range map[string]bool{"www.npmjs.com": true, "central.sonatype.com": true,
		"example.readthedocs.io": false, "example.com": false, "notnpmjs.com": false} {
		if got := c.RegistryHost(host); got != want {
			t.Errorf("RegistryHost(%q) = %v, want %v", host, got, want)
		}
	}
	if !c.HostingDomain("example.github.io") || c.HostingDomain("github.com") {
		t.Error("HostingDomain")
	}
}
