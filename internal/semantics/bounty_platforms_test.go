// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

func TestBountyPlatformsCatalog(t *testing.T) {
	ps := BountyPlatforms()
	if len(ps) < 4 {
		t.Fatalf("want at least 4 bounty platforms, got %d", len(ps))
	}

	h1, ok := BountyPlatformByKey("hackerone")
	if !ok {
		t.Fatal("hackerone missing")
	}
	if got := h1.ProgramPage("acme"); got != "https://hackerone.com/acme" {
		t.Errorf("ProgramPage = %q", got)
	}
	if !h1.OwnsHost("www.hackerone.com") || h1.OwnsHost("nothackerone.com") || h1.OwnsHost("bugcrowd.com") {
		t.Error("OwnsHost matched the wrong hosts")
	}
}
