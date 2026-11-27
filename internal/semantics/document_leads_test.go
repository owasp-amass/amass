// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

func TestGenericOrganizationName(t *testing.T) {
	cases := map[string]bool{
		"Counseling":                true,
		"Health Center":             true,
		"Rapid Response":            true,
		"Office of Financial Aid":   true,
		"Student Health & Wellness": true,
		"Northern Fire Systems":     false,
		"Teachers Insurance and Annuity Association of America": false,
		"Counseling Associates, Inc.":                           false,
		"Utica University":                                      false,
		"Example Research Inc.":                                 false,
		"":                                                      false,
		"of the":                                                false,
	}
	for name, want := range cases {
		if got := GenericOrganizationName(name); got != want {
			t.Errorf("GenericOrganizationName(%q) = %v, want %v", name, got, want)
		}
	}
}
