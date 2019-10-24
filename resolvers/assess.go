// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import "context"

// SanityChecks performs some basic checks to see if the resolvers are reliable.
func (rp *ResolverPool) SanityChecks() {
	for _, r := range rp.Resolvers {
		go func(res Resolver) {
			if !goodNamesResolved(res) {
				rp.Log.Printf("SanityChecks: Resolver %s failed to resolve good names", res.Address())
			}
		}(r)

		go func(res Resolver) {
			if !badNamesNotResolved(res) {
				rp.Log.Printf("SanityChecks: Resolver %s returned false positives for bad names", res.Address())
			}
		}(r)
	}
}

func goodNamesResolved(r Resolver) bool {
	results := make(chan bool, 10)
	goodNames := []string{
		"www.owasp.org",
		"twitter.com",
		"github.com",
		"www.google.com",
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Check that valid names can be resolved
	for _, name := range goodNames {
		go resolveForSanityCheck(ctx, r, name, false, results)
	}

	success := true
	var cancelled bool
	l := len(goodNames)
	for i := 0; i < l; i++ {
		select {
		case result := <-results:
			if !result {
				success = false
				cancelled = true
				cancel()
			}
		}
	}

	if !cancelled {
		cancel()
	}
	return success
}

func badNamesNotResolved(r Resolver) bool {
	results := make(chan bool, 10)
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

	ctx, cancel := context.WithCancel(context.Background())
	// Check that invalid names do not return false positives
	for _, name := range badNames {
		go resolveForSanityCheck(ctx, r, name, true, results)
	}

	success := true
	var cancelled bool
	l := len(badNames)
	for i := 0; i < l; i++ {
		select {
		case result := <-results:
			if !result {
				success = false
				cancelled = true
				cancel()
			}
		}
	}

	if !cancelled {
		cancel()
	}
	return success
}

func resolveForSanityCheck(ctx context.Context, r Resolver, name string, badname bool, ch chan bool) {
	var err error
	again := true
	var success bool

	for i := 0; i < 2 && again; i++ {
		_, again, err = r.Resolve(ctx, name, "A", PriorityCritical)
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
