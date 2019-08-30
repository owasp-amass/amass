// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

// SanityCheck performs some basic checks to see if the resolvers will be usable.
func SanityCheck(res []Resolver) []Resolver {
	f := func(r Resolver, name string, flip bool, ch chan Resolver) {
		var err error
		again := true
		var success bool

		for i := 0; i < 2 && again; i++ {
			_, again, err = r.Resolve(name, "A")
			if err == nil {
				success = true
				break
			}
		}

		if flip {
			success = !success
		}
		if !success {
			ch <- nil
			return
		}
		ch <- r
	}

	results := make(chan Resolver, 10)
	// Check that valid names can be resolved
	goodNames := []string{
		"www.owasp.org",
		"twitter.com",
		"github.com",
		"www.google.com",
	}
	for _, r := range res {
		for _, name := range goodNames {
			go f(r, name, false, results)
		}
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
	for _, r := range res {
		for _, name := range badNames {
			go f(r, name, true, results)
		}
	}

	var r []Resolver
	l := len(goodNames) + len(badNames)
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
