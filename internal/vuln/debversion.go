// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package vuln

import (
	"strconv"
	"strings"
)

// CompareDebian compares two Debian package versions
// ([epoch:]upstream[-revision]) as dpkg does (deb-version(7)): the epoch
// numerically, then the upstream version and the revision by alternating
// runs of non-digits and digits, where '~' sorts before anything, even the
// end, letters before other characters, and digit runs numerically. When
// only one version carries an epoch, both are compared without it: a
// version read from a banner never shows one.
func CompareDebian(a, b string) int {
	ea, ua, ra := splitDebian(a)
	eb, ub, rb := splitDebian(b)
	if ea != "" && eb != "" {
		na, _ := strconv.Atoi(ea)
		nb, _ := strconv.Atoi(eb)
		if na != nb {
			if na < nb {
				return -1
			}

			return 1
		}
	}

	if c := compareDebianPart(ua, ub); c != 0 {
		return c
	}

	return compareDebianPart(ra, rb)
}

// splitDebian splits a version into its epoch, upstream version and revision.
func splitDebian(v string) (string, string, string) {
	v = strings.TrimSpace(v)
	var epoch, rev string
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, v = v[:i], v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		v, rev = v[:i], v[i+1:]
	}

	return epoch, v, rev
}

// UpstreamDebian returns the upstream part of a Debian package version.
func UpstreamDebian(v string) string {
	_, u, _ := splitDebian(v)
	return u
}

func debianOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case c >= '0' && c <= '9':
		return 0
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	default:
		return int(c) + 256
	}
}

func compareDebianPart(a, b string) int {
	for a != "" || b != "" {
		// the non-digit run
		for (a != "" && !isDigit(a[0])) || (b != "" && !isDigit(b[0])) {
			var ca, cb int
			if a != "" && !isDigit(a[0]) {
				ca = debianOrder(a[0])
			}
			if b != "" && !isDigit(b[0]) {
				cb = debianOrder(b[0])
			}
			if ca != cb {
				if ca < cb {
					return -1
				}

				return 1
			}
			if a != "" && !isDigit(a[0]) {
				a = a[1:]
			}
			if b != "" && !isDigit(b[0]) {
				b = b[1:]
			}
		}

		// the digit run, compared as a number
		var da, db string
		for a != "" && isDigit(a[0]) {
			da, a = da+a[:1], a[1:]
		}
		for b != "" && isDigit(b[0]) {
			db, b = db+b[:1], b[1:]
		}

		da, db = strings.TrimLeft(da, "0"), strings.TrimLeft(db, "0")
		if len(da) != len(db) {
			if len(da) < len(db) {
				return -1
			}

			return 1
		}
		if c := strings.Compare(da, db); c != 0 {
			return c
		}
	}

	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
