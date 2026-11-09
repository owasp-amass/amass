// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package subs

import (
	"testing"

	amassnet "github.com/owasp-amass/amass/v5/internal/net"
)

func TestAddInfrastructureInfoPreservesDiscoveredNamesWithoutASNs(t *testing.T) {
	const scope = "owasp.org"
	names := []string{scope, "www." + scope, "wiki." + scope, "dev." + scope}
	lookup := make(outLookup, len(names))
	for _, name := range names {
		lookup[name] = &amassnet.Output{Name: name}
	}
	result := addInfrastructureInfo(lookup, amassnet.NewASNCache())
	if len(result) != len(names) {
		t.Fatalf("ASN enrichment incorrectly removed FQDNs: want=%d got=%d", len(names), len(result))
	}
	present := map[string]bool{}
	for _, out := range result {
		present[out.Name] = true
	}
	for _, name := range names {
		if !present[name] {
			t.Fatalf("missing discovered name %q after ASN enrichment", name)
		}
	}
}
