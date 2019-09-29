// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import "context"

// SanityCheck performs some basic checks to see if the resolvers will be usable.
func SanityCheck(res []Resolver) []Resolver {
	results := make(chan Resolver, 50)
	// Fire off the checks for each Resolver
	for _, r := range res {
		go checkSingleResolver(r, results)
	}

	l := len(res)
	var r []Resolver
	for i := 0; i < l; i++ {
		select {
		case result := <-results:
			if result != nil {
				r = append(r, result)
			}
		}
	}
	return r
}

func checkSingleResolver(r Resolver, ch chan Resolver) {
	results := make(chan bool, 10)
	// Check that valid names can be resolved
	goodNames := []string{
		"www.owasp.org",
		"twitter.com",
		"github.com",
		"www.google.com",
	}
	for _, name := range goodNames {
		go resolveForSanityCheck(r, name, false, results)
	}

	// Check that invalid names do not return false positives
	badNames := []string{
		"not-a-real-name.owasp.org",
		"wwww.owasp.org",
		"www-1.owasp.org",
		"www1.owasp.org",
		"wwww.google.com",
		"www-1.google.com",
		"www1.google.com",
		"not-a-real-name.google.com",
	}
	for _, name := range badNames {
		go resolveForSanityCheck(r, name, true, results)
	}

	answer := r
	l := len(goodNames) + len(badNames)
	for i := 0; i < l; i++ {
		select {
		case result := <-results:
			if result == false {
				answer = nil
			}
		}
	}

	ch <- answer
}

func resolveForSanityCheck(r Resolver, name string, badname bool, ch chan bool) {
	var err error
	again := true
	var success bool

	for i := 0; i < 2 && again; i++ {
		_, again, err = r.Resolve(context.TODO(), name, "A")
		if err == nil && !again {
			success = true
			break
		}
	}

	if badname {
		success = !success
	}

	ch <- success
}
