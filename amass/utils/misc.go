// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package utils

import (
	"regexp"
	"strings"
)

const (
	// IPv4RE is a regular expression that will match an IPv4 address.
	IPv4RE = "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.]){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
	// SUBRE is a regular expression that will match on all subdomains once the domain is appended.
	SUBRE = "(([_a-zA-Z0-9]{1}|[a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+"
)

// Semaphore implements a synchronization object
// type capable of being a counting semaphore.
type Semaphore struct {
	c chan struct{}
}

// NewSemaphore returns a Semaphore initialized to max resource counts.
func NewSemaphore(max int) *Semaphore {
	sem := &Semaphore{
		c: make(chan struct{}, max),
	}

	for i := 0; i < max; i++ {
		sem.c <- struct{}{}
	}
	return sem
}

// Acquire blocks until num resource counts have been obtained.
func (s *Semaphore) Acquire(num int) {
	for i := 0; i < num; i++ {
		<-s.c
	}
}

// TryAcquire attempts to obtain num resource counts without blocking.
// The method returns true when successful in acquiring the resource counts.
func (s *Semaphore) TryAcquire(num int) bool {
	var count int
loop:
	for i := 0; i < num; i++ {
		select {
		case <-s.c:
			count++
		default:
			break loop
		}
	}

	if count == num {
		return true
	}
	s.Release(count)
	return false
}

// Release causes num resource counts to be released.
func (s *Semaphore) Release(num int) {
	for i := 0; i < num; i++ {
		s.c <- struct{}{}
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
