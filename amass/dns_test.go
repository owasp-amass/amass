// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"testing"
)

func TestDNSQuery(t *testing.T) {
	name := "google.com"
	config := DefaultConfig()
	config.Setup()

	answers, err := config.dns.Query(name)
	if err != nil {
		t.Errorf("The DNS query for %s failed: %s", name, err)
	}

	if ip := GetARecordData(answers); ip == "" {
		t.Errorf("The query for %s was successful, yet did not return a A or AAAA record", name)
	}
}
