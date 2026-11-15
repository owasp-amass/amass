// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// A focused lens spends its asset limit on the types it reads and those
// that lead to them (the email lens skips the addresses), where an
// unfocused one shares it with every type.
func TestFocusedFootprintSpendsLimitOnWhatItReads(t *testing.T) {
	g := graphtest.ServicesFixture()
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("host%d.colgate.edu", i)
		g.Assets[name] = graph.Asset{ID: name, Type: "FQDN", Key: name, Content: map[string]any{"name": name}}
		g.Links = append(g.Links, graph.Relation{ID: "n" + name, FromID: "colgate.edu", ToID: name, Label: "node",
			Type: "SimpleRelation"})

		ip := fmt.Sprintf("192.0.2.%d", i)
		g.Assets[ip] = graph.Asset{ID: ip, Type: "IPAddress", Key: ip, Content: map[string]any{"address": ip}}
		g.Links = append(g.Links, graph.Relation{ID: "a" + ip, FromID: name, ToID: ip, Label: "dns_record",
			Type: "BasicDNSRelation", Content: map[string]any{"header": map[string]any{"rr_type": 1}}})
	}

	count := func(name string) map[string]int {
		s, err := newScope(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"],
			LensLimits{MaxAssets: 60}, name)
		if err != nil {
			t.Fatal(err)
		}
		if !s.report.Truncated {
			t.Fatalf("the %s footprint was not limited", name)
		}

		types := map[string]int{}
		for _, a := range s.owned {
			types[a.Type]++
		}

		return types
	}

	email, exposure := count("email"), count("exposure")
	if email["IPAddress"] != 0 || email["FQDN"] <= exposure["FQDN"] {
		t.Errorf("focused email footprint %v, unfocused exposure footprint %v", email, exposure)
	}
	if exposure["IPAddress"] == 0 {
		t.Errorf("the unfocused footprint sampled no addresses: %v", exposure)
	}
}

// Every focus entry names a registered lens and asset types the semantics
// table can reach.
func TestLensFocusEntries(t *testing.T) {
	for name, targets := range loadLensRules().Focus {
		if _, ok := SubjectLensNamed(name); !ok {
			t.Errorf("lens.json focus names an unknown lens %q", name)
		}
		if len(targets) == 0 {
			t.Errorf("lens.json focus for %s lists no types", name)
		}
		if !ControlledReachable(postureCatalog(), targets) {
			t.Errorf("lens.json focus for %s: %v cannot be reached from an organization", name, targets)
		}
	}
}

// Without an asset limit, focusing a lens does not change what it reports.
func TestFocusDoesNotChangeUnlimitedResults(t *testing.T) {
	for _, g := range []graphtest.VendorGraph{graphtest.ServicesFixture(), postureFixture()} {
		compareFocus(t, g, g.Assets["colgate.edu"])
	}
}

func compareFocus(t *testing.T, g graphtest.VendorGraph, root graph.Asset) {
	t.Helper()
	run := func() []string {
		ctx := context.Background()
		email, err := FindEmailSecurity(ctx, g, postureCatalog(), root, LensLimits{})
		if err != nil {
			t.Fatal(err)
		}

		domains, err := FindDomains(ctx, g, postureCatalog(), root, LensLimits{})
		if err != nil {
			t.Fatal(err)
		}

		certs, err := FindCertificates(ctx, g, postureCatalog(), root, LensLimits{})
		if err != nil {
			t.Fatal(err)
		}

		return []string{stripReadCounts(email.Text()), stripReadCounts(domains.Text()), stripReadCounts(certs.Text())}
	}

	focused := run()
	defer func(f func(string) []string) { lensFocus = f }(lensFocus)
	lensFocus = func(string) []string { return nil }
	unfocused := run()

	for i := range focused {
		if focused[i] != unfocused[i] && !onlyFootprintDiffers(focused[i], unfocused[i]) {
			t.Errorf("focused:\n%s\nunfocused:\n%s", focused[i], unfocused[i])
		}
	}
}

// stripReadCounts drops the footprint and read counts from a lens's first
// line, which a focused walk changes.
func stripReadCounts(text string) string {
	first, rest, _ := strings.Cut(text, "\n")
	if i := strings.Index(first, " from "); i > 0 {
		first = first[:i]
	}

	return first + "\n" + rest
}

func onlyFootprintDiffers(a, b string) bool { return stripReadCounts(a) == stripReadCounts(b) }
