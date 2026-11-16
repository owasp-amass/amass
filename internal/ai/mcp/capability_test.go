// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import "testing"

func TestCapabilityAvailableTo(t *testing.T) {
	read := capability{tier: tierRead}
	oper := capability{tier: tierOperator}

	if !read.availableTo(false) || !read.availableTo(true) {
		t.Error("a read capability should be available to every connection")
	}
	if oper.availableTo(false) {
		t.Error("an operator capability must not be available without operator mode")
	}
	if !oper.availableTo(true) {
		t.Error("an operator capability should be available in operator mode")
	}
}
