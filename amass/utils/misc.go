// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package utils

import (
	"regexp"
	"strings"
)

const (
	// An IPv4 regular expression
	IPv4RE = "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.]){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
	// This regular expression + the base domain will match on all names and subdomains
	SUBRE = "(([_a-zA-Z0-9]{1}|[a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+"
)

func SubdomainRegex(domain string) *regexp.Regexp {
	// Change all the periods into literal periods for the regex
	d := strings.Replace(domain, ".", "[.]", -1)

	return regexp.MustCompile(SUBRE + d)
}

func AnySubdomainRegex() *regexp.Regexp {
	return regexp.MustCompile(SUBRE + "[a-zA-Z0-9-]{0,61}[.][a-zA-Z]")
}

// NewUniqueElements - Removes elements that have duplicates in the original or new elements
func NewUniqueElements(orig []string, add ...string) []string {
	var n []string

	for _, av := range add {
		found := false
		s := strings.ToLower(av)

		// Check the original slice for duplicates
		for _, ov := range orig {
			if s == strings.ToLower(ov) {
				found = true
				break
			}
		}
		// Check that we didn't already add it in
		if !found {
			for _, nv := range n {
				if s == nv {
					found = true
					break
				}
			}
		}
		// If no duplicates were found, add the entry in
		if !found {
			n = append(n, s)
		}
	}
	return n
}

// UniqueAppend - Behaves like the Go append, but does not add duplicate elements
func UniqueAppend(orig []string, add ...string) []string {
	return append(orig, NewUniqueElements(orig, add...)...)
}

func CopyString(src string) string {
	str := make([]byte, len(src))

	copy(str, src)
	return string(str)
}