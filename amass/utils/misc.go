// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package utils

import (
	"regexp"
	"strings"

	"github.com/irfansharif/cfilter"
)

const (
	// IPv4RE is a regular expression that will match an IPv4 address.
	IPv4RE = "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.]){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
	// SUBRE is a regular expression that will match on all subdomains once the domain is appended.
	SUBRE = "(([_a-zA-Z0-9]{1}|[a-zA-Z0-9]{1}[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9]{1})[.]{1})+"
)

type filterRequest struct {
	String string
	Result chan bool
}

// StringFilter implements an object that performs filtering of strings
// to ensure that only unique items get through the filter.
type StringFilter struct {
	filter   *cfilter.CFilter
	requests chan filterRequest
	quit     chan struct{}
}

// NewStringFilter returns an initialized NameFilter.
func NewStringFilter() *StringFilter {
	sf := &StringFilter{
		filter:   cfilter.New(),
		requests: make(chan filterRequest),
		quit:     make(chan struct{}),
	}
	go sf.processRequests()
	return sf
}

// Duplicate checks if the name provided has been seen before by this filter.
func (sf *StringFilter) Duplicate(s string) bool {
	result := make(chan bool)

	sf.requests <- filterRequest{String: s, Result: result}
	return <-result
}

func (sf *StringFilter) processRequests() {
	for {
		select {
		case <-sf.quit:
			return
		case r := <-sf.requests:
			if sf.filter.Lookup([]byte(r.String)) {
				r.Result <- true
			} else {
				sf.filter.Insert([]byte(r.String))
				r.Result <- false
			}
		}
	}
}

// SubdomainRegex returns a Regexp object initialized to match
// subdomain names that end with the domain provided by the parameter.
func SubdomainRegex(domain string) *regexp.Regexp {
	// Change all the periods into literal periods for the regex
	d := strings.Replace(domain, ".", "[.]", -1)

	return regexp.MustCompile(SUBRE + d)
}

// AnySubdomainRegex returns a Regexp object initialized to match any DNS subdomain name.
func AnySubdomainRegex() *regexp.Regexp {
	return regexp.MustCompile(SUBRE + "[a-zA-Z0-9-]{0,61}[.][a-zA-Z]{0,61}")
}

// NewUniqueElements removes elements that have duplicates in the original or new elements.
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

// UniqueAppend behaves like the Go append, but does not add duplicate elements.
func UniqueAppend(orig []string, add ...string) []string {
	return append(orig, NewUniqueElements(orig, add...)...)
}

// CopyString return a new string variable with the same value as the parameter.
func CopyString(src string) string {
	str := make([]byte, len(src))

	copy(str, src)
	return string(str)
}

// RemoveAsteriskLabel returns the provided DNS name with all asterisk labels removed.
func RemoveAsteriskLabel(s string) string {
	var index int

	labels := strings.Split(s, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		if strings.TrimSpace(labels[i]) == "*" {
			break
		}
		index = i
	}
	if index == len(labels)-1 {
		return ""
	}
	return strings.Join(labels[index:], ".")
}
