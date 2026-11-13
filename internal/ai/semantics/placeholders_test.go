// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

func TestIsPlaceholderOrganization(t *testing.T) {
	for name, want := range map[string]bool{
		"Registration Private":                    true,
		"REDACTED FOR PRIVACY":                    true,
		"Domain Admin":                            true,
		"Administrator, Domain ContactMiddleName": true,
		"On behalf of credittransfer.org owner":   true,
		"  n/a ":                                  true,
		"SomeOrganization":                        true,
		"Internet Widgits Pty Ltd":                true,
		"Default Company Ltd":                     true,
		"Acme Co":                                 true,
		"Acme Corporation":                        false,
		"Colgate University":                      false,
		"ProxyMesh, Inc.":                         false,
		"Privacy International":                   false,
		"Internet Security Research Group":        false,
		"The Private Bank of California":          false,
		"Domain Administration Services Pty Ltd":  false,
		"":                                        false,
	} {
		if got := IsPlaceholderOrganization(name); got != want {
			t.Errorf("IsPlaceholderOrganization(%q) = %v, want %v", name, got, want)
		}
	}
}
