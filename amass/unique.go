// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"regexp"
	"strings"
)

const (
	SUBRE = "(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])[.])+"
	IPRE  = "(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9]?)([.](25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9]?)){3}"
)

func NewUniqueElements(orig []string, add ...string) []string {
	var n []string

	for _, av := range add {
		found := false
		s := strings.ToLower(av)

		for _, ov := range orig {
			if s == ov {
				found = true
			}
		}

		for _, nv := range n {
			if s == nv {
				found = true
			}
		}

		if !found {
			n = append(n, s)
		}
	}
	return n
}

func UniqueAppend(orig []string, add ...string) []string {
	return append(orig, NewUniqueElements(orig, add...)...)
}

func Trim252F(subdomain string) string {
	s := strings.ToLower(subdomain)

	re, err := regexp.Compile("^((252f)|(2f)|(3d))+")
	if err != nil {
		return s
	}

	i := re.FindStringIndex(s)
	if i != nil {
		return s[i[1]:]
	}
	return s
}

func ExtractDomain(subdomain string) string {
	p := strings.Split(subdomain, ".")
	l := len(p)

	if l == 1 {
		return ""
	}

	return strings.Join(p[l-2:], ".")
}
