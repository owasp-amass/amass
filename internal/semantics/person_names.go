// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"strings"

	fnparser "github.com/caffix/fullname_parser"
)

// PersonName is a person's name split into its parts, and the full name
// written from them.
type PersonName struct {
	Full, First, Middle, Last string
}

// ParsePersonName splits a raw name as a person's, and reports false when
// it does not split into a given name and a family name (a single word, or
// what the parser cannot place). The full name is written title, given,
// middle and family name, then the suffix after a comma.
func ParsePersonName(raw string) (PersonName, bool) {
	if raw == "" || len(strings.Split(raw, " ")) == 1 {
		return PersonName{}, false
	}

	name := fnparser.ParseFullname(raw)
	if name.First == "" || name.Last == "" {
		return PersonName{}, false
	}

	var full string
	if name.Title != "" {
		full += name.Title + " "
	}
	full += name.First + " "
	if name.Middle != "" {
		full += name.Middle + " "
	}
	full += name.Last
	if name.Suffix != "" {
		full += ", " + name.Suffix
	}

	return PersonName{Full: full, First: name.First, Middle: name.Middle, Last: name.Last}, true
}
