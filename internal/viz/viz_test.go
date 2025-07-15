// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package viz

func testEdges() []Edge {
	return []Edge{
		{
			From:  0,
			To:    1,
			Label: "a_record",
			Title: "a_record",
		},
	}
}

func testNodes() []Node {
	return []Node{
		{
			ID:    0,
			Type:  "FQDN",
			Label: "owasp.org",
			Title: "FQDN: owasp.org",
		},
		{
			ID:    1,
			Type:  "IPAddress",
			Label: "205.251.199.98",
			Title: "IPAddress: 205.251.199.98",
		},
	}
}
