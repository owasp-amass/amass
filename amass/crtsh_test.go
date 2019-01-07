// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

/*
import (
	"sync"
	"testing"
)

func TestCrtsh(t *testing.T) {

	expected := 100
	e := NewEnumeration()
	var wg sync.WaitGroup

	e.Config.Passive = true
	e.Config.AddDomain("letsencrypt.owasp-amass.com")
	e.dataSources = []Service{NewCrtsh(e)}

	results := make(map[string]bool)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			req, ok := <-e.Output
			if !ok {
				break
			}
			results[req.Name] = true

		}
	}()

	e.Start()
	wg.Wait()

	if expected != len(results) {
		t.Errorf("Found %d names, expected %d instead", len(results), expected)
	}

}
*/
