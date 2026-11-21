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

	// network is the unfocused example: it has no focus entry and, unlike the
	// summarizing lenses (cloud, services, exposure, ...), keeps every member
	// address of a held netblock, so it still samples addresses here.
	email, network := count("email"), count("network")
	if email["IPAddress"] != 0 || email["FQDN"] <= network["FQDN"] {
		t.Errorf("focused email footprint %v, unfocused network footprint %v", email, network)
	}
	if network["IPAddress"] == 0 {
		t.Errorf("the unfocused footprint sampled no addresses: %v", network)
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

// The summarizing lenses (cloud, services, ...) skip a held netblock's member
// addresses that host nothing, count them, and say so in their header; the
// address-space lenses (network) still keep every member address.
func TestSummarizeBareNetblockAddresses(t *testing.T) {
	g := graphtest.ServicesFixture()
	const bare = 20
	for i := 0; i < bare; i++ {
		ip := fmt.Sprintf("149.43.200.%d", i)
		g.Assets[ip] = graph.Asset{ID: ip, Type: "IPAddress", Key: ip, Content: map[string]any{"address": ip}}
		g.Links = append(g.Links, graph.Relation{ID: "nb-own-contains-" + ip, FromID: "nb-own", ToID: ip,
			Label: "contains", Type: "SimpleRelation"})
	}
	root := g.Assets["colgate.edu"]

	addresses := func(owned map[string]graph.Asset) (bareKept int, hostKept bool) {
		for id, a := range owned {
			if a.Type != "IPAddress" {
				continue
			}
			if strings.HasPrefix(id, "149.43.200.") {
				bareKept++
			}
			if id == "ip-own" {
				hostKept = true
			}
		}
		return bareKept, hostKept
	}

	cloud, err := newScope(context.Background(), g, postureCatalog(), root, LensLimits{}, LensCloud)
	if err != nil {
		t.Fatal(err)
	}
	if n, host := addresses(cloud.owned); n != 0 || !host {
		t.Errorf("cloud footprint kept %d bare addresses (want 0) and the hosting address: %v", n, host)
	}
	if got := cloud.base().SummarizedAddresses; got != bare {
		t.Errorf("cloud summarized %d addresses, want %d", got, bare)
	}
	if note := cloud.base().summarizedNote(); !strings.HasPrefix(note, "20 address(es) in held netblocks") {
		t.Errorf("cloud summarized note = %q", note)
	}

	network, err := newScope(context.Background(), g, postureCatalog(), root, LensLimits{}, "network")
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := addresses(network.owned); n != bare {
		t.Errorf("network footprint kept %d bare addresses, want all %d", n, bare)
	}
	if network.base().summarizedNote() != "" {
		t.Errorf("network reported summarized addresses: %d", network.base().SummarizedAddresses)
	}

	services, err := FindServices(context.Background(), g, postureCatalog(), root, LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if services.SummarizedAddresses != bare ||
		!strings.Contains(services.Text(), "20 address(es) in held netblocks host no stored name or service") {
		t.Errorf("services summarized %d addresses; report:\n%s", services.SummarizedAddresses, services.Text())
	}
}

func TestSummarizedNote(t *testing.T) {
	if summarizedNote(0) != "" {
		t.Error("no summarized addresses should add no line")
	}
	if got := summarizedNote(2168); !strings.HasPrefix(got, "2168 address(es)") || !strings.HasSuffix(got, "\n") {
		t.Errorf("summarizedNote(2168) = %q", got)
	}
}
