// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package docmeta

import "testing"

func TestAuthorForms(t *testing.T) {
	for raw, want := range map[string]string{"(Jane Doe)": "Jane Doe", " 'jdoe' ": "jdoe", "Jane Doe": "Jane Doe"} {
		if got := Unwrap(raw); got != want {
			t.Errorf("Unwrap(%q) = %q, want %q", raw, got, want)
		}
	}

	for raw, want := range map[string]string{"jdoe": "jdoe", "jane.doe": "jane.doe", "jdoe2": "jdoe2",
		"j_doe-1": "j_doe-1", `UTICA\JDoe`: "JDoe", "tony": "tony"} {
		if got, ok := LoginName(raw); !ok || got != want {
			t.Errorf("LoginName(%q) = %q, %v, want %q", raw, got, ok, want)
		}
	}
	for _, raw := range []string{"Jane Doe", "Jane", "JDoe", "administrator", "guest", "j", "2024", `\jdoe`,
		`OWASP FOUNDATION\jdoe`, "josé", "jane doe"} {
		if got, ok := LoginName(raw); ok {
			t.Errorf("LoginName(%q) = %q, an account", raw, got)
		}
	}

	for _, raw := range []string{"JD", "J.D.", "JQD", "ABCD", "S.P.H"} {
		if !Initials(raw) {
			t.Errorf("%q is initials", raw)
		}
	}
	for _, raw := range []string{"J", "ABCDE", "Jo", "J..D", "jd", "Jane Doe", "OWASP"} {
		if Initials(raw) {
			t.Errorf("%q is not initials", raw)
		}
	}
}
