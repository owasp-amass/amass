// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"testing"
)

func TestShodan(t *testing.T) {
	if *networkTest == false || *configPath == "" {
		return
	}

	api := testConfig.GetAPIKey("Shodan")
	if api == nil || api.Key == "" {
		return
	}

	result := testDNSRequest("Shodan")
	if result < expectedTest {
		t.Errorf("Found %d names, expected at least %d instead", result, expectedTest)
	}
}
