// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package docmeta

import "strings"

// Unwrap removes the brackets and quotes office software and conversion
// tools leave around an author ("(Jane Doe)", "'jdoe'").
func Unwrap(author string) string {
	return strings.TrimSpace(strings.Trim(strings.TrimSpace(author), `()[]{}"'`))
}

// LoginName returns the account name an author field holds instead of a
// person's name: the computer's user name, which office software writes
// when no name was set. It is one lower-case word of letters and digits,
// perhaps joined by dots, underscores or hyphens (jdoe, jane.doe, jdoe2), or
// a directory's DOMAIN\user form. A capitalized word ("Jane") may be a given
// name and is left to the name rules, and a folder name that names no one
// (administrator, guest) is not an account.
func LoginName(author string) (string, bool) {
	name, lower := author, true
	if domain, user, ok := strings.Cut(author, `\`); ok {
		if domain == "" || strings.ContainsAny(domain, ` \`) {
			return "", false
		}
		name, lower = user, false
	}
	if len(name) < 2 || len(name) > 64 || ignoredUser[strings.ToLower(name)] {
		return "", false
	}

	letter := false
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			letter = true
		case r >= 'A' && r <= 'Z' && !lower:
			letter = true
		case r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return "", false
		}
	}
	if !letter {
		return "", false
	}

	return name, true
}

// Initials reports whether an author field holds only initials (JD, J.D.,
// JQD): two to four capital letters, perhaps each followed by a dot. They
// name no one that can be told apart.
func Initials(author string) bool {
	letters := 0
	for i, r := range author {
		switch {
		case r >= 'A' && r <= 'Z':
			letters++
		case r == '.' && i > 0 && author[i-1] != '.':
		default:
			return false
		}
	}
	return letters >= 2 && letters <= 4
}
