// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"testing"
	"time"
)

func TestClientSubnetCheck(t *testing.T) {
	good := []string{
		"8.8.8.8:53",     // Google
		"1.1.1.1:53",     // Cloudflare
		"209.244.0.3:53", // Level3
	}
	bad := []string{
		"198.101.242.72:53", // Alternate DNS
		"208.76.50.50:53",   // SmartViper
	}

	for _, r := range good {
		if err := ClientSubnetCheck(r); err != nil {
			t.Errorf("%v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	for _, r := range bad {
		if err := ClientSubnetCheck(r); err == nil {
			t.Errorf("%s should have failed the test", r)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
