// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"testing"
)

func TestBruteForceService(t *testing.T) {
	domains := []string{"claritysec.com", "twitter.com", "google.com", "github.com"}

	in := make(chan *AmassRequest)
	out := make(chan *AmassRequest)
	config := CustomConfig(&AmassConfig{
		Domains:      domains,
		Wordlist:     []string{"foo", "bar"},
		BruteForcing: true,
	})
	srv := NewBruteForceService(in, out, config)
	srv.Start()

	// Setup the results we expect to see
	results := make(map[string]int)
	for _, domain := range domains {
		for _, word := range config.Wordlist {
			results[word+"."+domain] = 0
		}
	}

	num := len(results)
	for i := 0; i < num; i++ {
		req := <-out

		results[req.Name]++
	}

	if num != len(results) {
		t.Errorf("BruteForce should have returned %d names, yet returned %d instead", num, len(results))
	}

	for name, times := range results {
		if times != 1 {
			t.Errorf("BruteForce returned a subdomain name, %s, %d number of times", name, times)
		}
	}

	srv.Stop()
}
