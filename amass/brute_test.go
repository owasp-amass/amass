// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"testing"
	"time"

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
	timer := time.NewTicker(time.Millisecond * 400)
	defer timer.Stop()

	expected := len(e.Config.Wordlist) * len(domains)
	results := make(map[string]int)

loop:
	for {
		select {
		case res := <-e.Output:
			results[res.Name]++
		case <-timer.C:
			// break on a max 400 ms for this test
			break loop
		}
	}

	if expected != len(results) {
		t.Errorf("BruteForce should have returned %d names, yet returned %d instead", expected, len(results))
	}
}
