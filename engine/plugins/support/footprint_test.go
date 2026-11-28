// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import "testing"

// A footprint ties addresses and URLs in any of its domains, and names the
// domain that tied them.
func TestFootprint(t *testing.T) {
	f := Footprint{"example.com", "example-labs.org"}
	if f.Address("Dev@Mail.Example.com") != "example.com" || f.Address("dev@notexample.com") != "" ||
		f.Address("example.com") != "" || f.Address("ops@example-labs.org") != "example-labs.org" {
		t.Error("Address")
	}
	if f.Host("git+https://www.example.com/x") != "example.com" || f.Host("https://example.com.evil.org") != "" ||
		f.Host("https://docs.example-labs.org/") != "example-labs.org" {
		t.Error("Host")
	}
}
