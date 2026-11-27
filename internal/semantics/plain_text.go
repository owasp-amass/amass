// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"strings"
	"unicode"

	"golang.org/x/text/transform"
)

// PlainText returns s folded to plain lower case, accents removed, with each
// run of characters that are not letters or digits read as one space, so text
// compares without casing, accent or punctuation noise ("José  O'Neil." is
// "jose o neil"). Organization names compare by OrgNameKey instead.
func PlainText(s string) string {
	folded, _, err := transform.String(foldAccents(), s)
	if err != nil {
		folded = s
	}

	return strings.Join(strings.FieldsFunc(strings.ToLower(folded), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}), " ")
}
