// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"sync"
	"testing"
	"time"
)

func TestCrtsh(t *testing.T) {
	if *datasources == false {
		return
	}

	expected := 100
	e := NewEnumeration()
	var wg sync.WaitGroup

	e.Config.Passive = true
	e.Config.AddDomain("letsencrypt.owasp-amass.com")
	e.dataSources = []Service{NewCrtsh(e)}

	results := make(map[string]struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTimer(10 * time.Second)
		defer t.Stop()

		for {
			select {
			case req := <-e.Output:
				results[req.Name] = struct{}{}
				if expected == len(results) {
					return
				}
			case <-t.C:
				return
			}
		}
	}()

	e.Start()
	wg.Wait()

	if expected != len(results) {
		t.Errorf("Found %d names, expected %d instead", len(results), expected)
	}
}
