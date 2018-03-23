// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"testing"

	"github.com/caffix/recon"
)

func TestResolversPublicServers(t *testing.T) {
	name := "google.com"

	for _, server := range knownPublicServers {
		_, err := recon.ResolveDNS(name, server, "A")
		if err != nil {
			t.Errorf("Public DNS server (%s) failed to resolve (%s)", server, name)
		}
	}
}
