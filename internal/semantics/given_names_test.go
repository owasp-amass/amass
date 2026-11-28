// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

func TestGivenNameForms(t *testing.T) {
	for _, pair := range [][2]string{{"robert", "bob"}, {"Bill", "william"}, {"ted", "edward"}, {"ted", "theodore"},
		{"kate", "Catherine"}} {
		if !GivenNameForms(pair[0], pair[1]) {
			t.Errorf("%s and %s are forms of one name", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{{"edward", "theodore"}, {"robert", "william"}, {"jane", "jane"}, {"", "bob"},
		{"henry", "harold"}} {
		if GivenNameForms(pair[0], pair[1]) {
			t.Errorf("%q and %q are not forms of one name", pair[0], pair[1])
		}
	}
}
