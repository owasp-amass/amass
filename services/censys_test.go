// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"testing"
)

func TestCensysAPIRequest(t *testing.T) {
	if *networkTest == false || *configPath == "" {
		return
	}

	api := testConfig.GetAPIKey("Censys")
	if api == nil || api.Key == "" || api.Secret == "" {
		return
	}

	result := testDNSRequest("Censys")
	if result < expectedTest {
		t.Errorf("Found %d names, expected at least %d instead", result, expectedTest)
	}
}

func TestCensysWebRequest(t *testing.T) {
	if *networkTest == false {
		return
	}

	if api := testConfig.GetAPIKey("Censys"); api != nil {
		key := api.Key
		secret := api.Secret

		defer func() {
			api.Key = key
			api.Secret = secret
			testConfig.AddAPIKey("Censys", api)
		}()

		api.Key = ""
		api.Secret = ""
		testConfig.AddAPIKey("Censys", api)
	}

	result := testDNSRequest("Censys")
	if result < expectedTest {
		t.Errorf("Found %d names, expected at least %d instead", result, expectedTest)
	}
}
