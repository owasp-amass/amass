// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dns

import (
	"regexp"
	"strings"
)

// SUBRE is a regular expression that will match on all subdomains once the domain is appended.
const SUBRE = "(([a-zA-Z0-9]{1}|[_a-zA-Z0-9]{1}[_a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+"

// SubdomainRegex returns a Regexp object initialized to match
// subdomain names that end with the domain provided by the parameter.
func SubdomainRegex(domain string) *regexp.Regexp {
	// Change all the periods into literal periods for the regex
	d := strings.Replace(domain, ".", "[.]", -1)

	return regexp.MustCompile(SUBRE + d)
}

// AnySubdomainRegex returns a Regexp object initialized to match any DNS subdomain name.
func AnySubdomainRegex() *regexp.Regexp {
	return regexp.MustCompile(SUBRE + "[a-zA-Z]{0,61}")
}

// CopyString return a new string variable with the same value as the parameter.
func CopyString(src string) string {
	str := make([]byte, len(src))

	copy(str, src)
	return string(str)
}

// RemoveAsteriskLabel returns the provided DNS name with all asterisk labels removed.
func RemoveAsteriskLabel(s string) string {
	startIndex := strings.LastIndex(s, "*.") + 2
	return s[startIndex:]
}

// ReverseString returns the characters of the argument string in reverse order.
func ReverseString(s string) string {
	chrs := []rune(s)

	end := len(chrs) / 2
	for i, j := 0, len(chrs)-1; i < end; i, j = i+1, j-1 {
		chrs[i], chrs[j] = chrs[j], chrs[i]
	}
	return string(chrs)
}
