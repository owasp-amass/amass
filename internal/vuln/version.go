// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package vuln

import (
	"strconv"
	"strings"
	"unicode"
)

// preRelease words sort before the release they precede (2.0.0-rc1 is
// before 2.0.0); other letters sort after (1.1.1k, 8.9p1).
var preRelease = map[string]bool{"alpha": true, "beta": true, "rc": true, "pre": true, "dev": true,
	"preview": true}

// versionTokens splits a version into runs of digits and of letters.
func versionTokens(v string) []string {
	var out []string
	var cur []rune
	kind := 0 // 1 digits, 2 letters
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for _, r := range v {
		k := 0
		switch {
		case unicode.IsDigit(r):
			k = 1
		case unicode.IsLetter(r):
			k = 2
		}
		if k == 0 || k != kind {
			flush()
		}
		if k != 0 {
			cur = append(cur, r)
		}

		kind = k
	}

	flush()

	return out
}

// CompareVersions orders two version strings: negative when a is before b,
// zero when they are the same release, positive when a is after b.
func CompareVersions(a, b string) int {
	ta, tb := versionTokens(a), versionTokens(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		// A missing number is zero: 3.0 is 3.0.0.
		switch {
		case i >= len(ta) && tb[i] == strings.Repeat("0", len(tb[i])):
			continue
		case i >= len(tb) && ta[i] == strings.Repeat("0", len(ta[i])):
			continue
		case i >= len(ta):
			return -tailOrder(tb[i])
		case i >= len(tb):
			return tailOrder(ta[i])
		}

		na, ea := strconv.Atoi(ta[i])
		nb, eb := strconv.Atoi(tb[i])
		switch {
		case ea == nil && eb == nil:
			if na != nb {
				return compareInt(na, nb)
			}
		case ea == nil:
			// A number is after a pre-release word and before other letters.
			if preRelease[tb[i]] {
				return 1
			}

			return -1
		case eb == nil:
			if preRelease[ta[i]] {
				return -1
			}

			return 1
		default:
			if c := strings.Compare(ta[i], tb[i]); c != 0 {
				return c
			}
		}
	}

	return 0
}

// tailOrder is how a version with one more token compares with the same
// version without it: 1.1.1k and 1.0.1 are after, 2.0.0rc1 before.
func tailOrder(tok string) int {
	if preRelease[tok] {
		return -1
	}

	return 1
}

func compareInt(a, b int) int {
	if a < b {
		return -1
	}

	return 1
}

// Covers reports whether the range includes version.
func (r Range) Covers(version string) bool {
	if r.Version != "" {
		return CompareVersions(version, r.Version) == 0
	}
	if r.StartIncl != "" && CompareVersions(version, r.StartIncl) < 0 {
		return false
	}
	if r.StartExcl != "" && CompareVersions(version, r.StartExcl) <= 0 {
		return false
	}
	if r.EndIncl != "" && CompareVersions(version, r.EndIncl) > 0 {
		return false
	}
	if r.EndExcl != "" && CompareVersions(version, r.EndExcl) >= 0 {
		return false
	}

	return true
}
