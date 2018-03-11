// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"testing"
)

func TestBruteForceService(t *testing.T) {
	var results []string

	in := make(chan *AmassRequest)
	out := make(chan *AmassRequest)
	srv := NewBruteForceService(in, out)

	words := []string{"foo", "bar"}
	srv.SetWordlist(words)
	srv.Start()

	domain := "claritysec.com"
	in <- &AmassRequest{
		Name:   domain,
		Domain: domain,
	}

	var num int
	for i := 0; i < len(words); i++ {
		req := <-out

		num++
		results = append(results, req.Name)
	}

	if num != len(words) {
		t.Errorf("BruteForce returned only %d requests", num)
	}

	for _, name := range results {
		if name != "foo.claritysec.com" && name != "bar.claritysec.com" {
			t.Errorf("BruteForce returned an incorrectly generated subdomain name: %s", name)
		}
	}

	srv.Stop()
}
