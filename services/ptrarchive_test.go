// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"testing"

	"github.com/OWASP/Amass/v3/net/http"
)

func TestPTRArchive(t *testing.T) {
	if *networkTest == false {
		return
	}

	result := testDNSRequest("PTRArchive")
	if result < expectedTest {
		t.Errorf("Found %d names, expected at least %d instead", result, expectedTest)
	}
}

func TestPTRArchiveEndpoint(t *testing.T) {
	if *networkTest == false {
		return
	}

	var endpoint string
	var ptr *PTRArchive
	var err error

	ptr = NewPTRArchive(testSystem)
	endpoint = ptr.getURL(domainTest)

	_, err = http.RequestWebPage(endpoint, nil, nil, "", "")

	if err != nil {
		if err.Error() == "404 Not Found" {
			t.Errorf("ptr Web API's name has changed: %s", endpoint)
		}
	}
}
