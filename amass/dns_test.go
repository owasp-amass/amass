// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"testing"

	"github.com/caffix/recon"
)

func TestDNSQuery(t *testing.T) {
	name := "google.com"
	server := "8.8.8.8:53"

	answers, err := DNS.Query(name, server)
	if err != nil {
		t.Errorf("The DNS query for %s using the %s server failed: %s", name, server, err)
	}

	if ip := recon.GetARecordData(answers); ip == "" {
		t.Errorf("The query for %s was successful, yet did not return a A or AAAA record", name)
	}
}
