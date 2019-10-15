// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"testing"
)

func TestHackerone(t *testing.T) {
	if *networkTest == false {
		return
	}

	cfg := testConfig
	defer func() {
		testConfig = cfg
	}()

	testConfig = setupConfig("twitter.com")

	result := testDNSRequest("HackerOne")
	if result < expectedTest {
		t.Errorf("Found %d names, expected at least %d instead", result, expectedTest)
	}
}
