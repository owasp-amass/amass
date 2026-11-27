// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

func TestPlainText(t *testing.T) {
	for in, want := range map[string]string{
		"José  O'Neil.":         "jose o neil",
		"13 Oak Drive, Suite 4": "13 oak drive suite 4",
		"Straße":                "straße",
		"  --  ":                "",
		"":                      "",
	} {
		if got := PlainText(in); got != want {
			t.Errorf("PlainText(%q) = %q, want %q", in, got, want)
		}
	}
}
