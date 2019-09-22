// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

// SanityCheck performs some basic checks to see if the resolvers will be usable.
func SanityCheck(res []Resolver) []Resolver {
	f := func(r Resolver, name string, ch chan Resolver) {
		var err error
		again := true
		var success bool

		for i := 0; i < 2 && again; i++ {
			_, again, err = r.Resolve(name, "A")
			if err != nil && !again {
				success = true
				break
			}
		}

		if !success {
			ch <- nil
			return
		}
		ch <- r
	}

	results := make(chan Resolver, 50)
	// Check that invalid names do not return false positives
	for _, r := range res {
		go f(r, "not-a-real-name.owasp.org", results)
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
