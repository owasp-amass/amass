// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"testing"

	"github.com/OWASP/Amass/amass/utils"
)

func TestBruteForceService(t *testing.T) {
	domains := []string{"claritysec.com", "twitter.com", "google.com", "github.com"}

	e := NewEnumeration()

	e.Config.Wordlist = []string{"foo", "bar"}
	e.Config.BruteForcing = true
	e.Config.Passive = true
	e.Config.AddDomains(domains)
	e.MaxFlow = utils.NewTimedSemaphore(e.Config.Timing.ToMaxFlow(), e.Config.Timing.ToReleaseDelay())

	e.bruteService.Start()
	defer e.bruteService.Stop()
	e.nameService.Start()
	defer e.nameService.Stop()

	// Setup the results we expect to see
	results := make(map[string]int)
	for _, domain := range domains {
		for _, word := range e.Config.Wordlist {
			results[word+"."+domain] = 0
		}
	}

	num := len(results)
	for i := 0; i < num; i++ {
		res := <-e.Output
		results[res.Name]++
	}

	if num != len(results) {
		t.Errorf("BruteForce should have returned %d names, yet returned %d instead", num, len(results))
	}

	for name, times := range results {
		if times != 1 {
			t.Errorf("BruteForce returned a subdomain name, %s, %d number of times", name, times)
		}
	}

}
