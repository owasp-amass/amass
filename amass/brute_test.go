// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"testing"
)

func TestBruteForce(t *testing.T) {
	var results []string
	domain := "claritysec.com"

	a := NewAmass()

	a.Wordlist = []string{"foo", "bar"}
	go a.BruteForce(domain, domain)

	for i := 0; i < len(a.Wordlist); i++ {
		sub := <-a.Names

		results = append(results, sub.Name)
	}

	for _, name := range results {
		if name != "foo.claritysec.com" && name != "bar.claritysec.com" {
			t.Errorf("BruteForce returned an incorrectly generated subdomain name: %s", name)
		}
	}
}
