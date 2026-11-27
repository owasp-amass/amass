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
		name := fmt.Sprintf("host%d.owasp.org", i)
		g.Assets[name] = graph.Asset{ID: name, Type: "FQDN", Key: name, Content: map[string]any{"name": name}}
		g.Links = append(g.Links, graph.Relation{ID: "n" + name, FromID: "owasp.org", ToID: name, Label: "node",
			Type: "SimpleRelation"})

		ip := fmt.Sprintf("192.0.2.%d", i)
		g.Assets[ip] = graph.Asset{ID: ip, Type: "IPAddress", Key: ip, Content: map[string]any{"address": ip}}
		g.Links = append(g.Links, graph.Relation{ID: "a" + ip, FromID: name, ToID: ip, Label: "dns_record",
			Type: "BasicDNSRelation", Content: map[string]any{"header": map[string]any{"rr_type": 1}}})
	}

	count := func(name string) map[string]int {
		s, err := newScope(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{}, name)
		if err != nil {
			t.Fatal(err)
		}
		if s.report.Truncated {
			t.Fatalf("the %s footprint was cut short: %s", name, s.report.Reason)
		}

		types := map[string]int{}
		for _, a := range s.owned {
			types[a.Type]++
		}

		return types
	}

	// network is the unfocused example: it has no focus entry and, unlike the
	// summarizing lenses (cloud, services, exposure, ...), keeps every member
	// address of a held netblock.
	email, network := count("email"), count("network")
	if email["IPAddress"] != 0 || email["FQDN"] != network["FQDN"] {
		t.Errorf("focused email footprint %v, unfocused network footprint %v", email, network)
	}
	if network["IPAddress"] == 0 {
		t.Errorf("the unfocused footprint has no addresses: %v", network)
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
		compareFocus(t, g, g.Assets["owasp.org"])
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
		ip := fmt.Sprintf("203.0.113.2%d", i)
		g.Assets[ip] = graph.Asset{ID: ip, Type: "IPAddress", Key: ip, Content: map[string]any{"address": ip}}
		g.Links = append(g.Links, graph.Relation{ID: "nb-own-contains-" + ip, FromID: "nb-own", ToID: ip,
			Label: "contains", Type: "SimpleRelation"})
	}
	root := g.Assets["owasp.org"]

	addresses := func(owned map[string]graph.Asset) (bareKept int, hostKept bool) {
		for id, a := range owned {
			if a.Type != "IPAddress" {
				continue
			}
			if strings.HasPrefix(id, "203.0.113.2") {
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

// A lens that never reads URLs leaves out the pages under the footprint's host
// names (counting them) but still admits the organization's website URL; a
// lens that reads URLs keeps them all.
func TestLensesThatDoNotReadURLsSkipHostedURLs(t *testing.T) {
	g := graphtest.ServicesFixture()
	const pages = 50
	for i := 0; i < pages; i++ {
		raw := fmt.Sprintf("https://www.owasp.org/page/%d", i)
		g.Assets[raw] = graph.Asset{ID: raw, Type: "URL", Key: raw, Content: map[string]any{"url": raw}}
		g.Links = append(g.Links, graph.Relation{ID: raw + "-domain", FromID: raw, ToID: "www.owasp.org",
			Label: "domain", Type: "SimpleRelation"})
	}
	site := "https://www.owasp.org/"
	g.Assets[site] = graph.Asset{ID: site, Type: "URL", Key: site, Content: map[string]any{"url": site}}
	g.Links = append(g.Links,
		graph.Relation{ID: "owasp-website", FromID: "owasp", ToID: site, Label: "website", Type: "SimpleRelation"},
		graph.Relation{ID: "site-domain", FromID: site, ToID: "www.owasp.org", Label: "domain",
			Type: "SimpleRelation"})

	urls := func(name string) (pageCount int, siteKept bool, skipped int) {
		s, err := newScope(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{}, name)
		if err != nil {
			t.Fatal(err)
		}
		for id, a := range s.owned {
			if a.Type != "URL" {
				continue
			}
			if id == site {
				siteKept = true
			} else if strings.HasPrefix(id, "https://www.owasp.org/page/") {
				pageCount++
			}
		}
		return pageCount, siteKept, s.report.SkippedURLs
	}

	if n, kept, skipped := urls(LensCloud); n != 0 || !kept || skipped != pages {
		t.Errorf("cloud kept %d pages (want 0), website kept %v, skipped %d (want %d)", n, kept, skipped, pages)
	}
	if n, kept, skipped := urls(LensWeb); n != pages || !kept || skipped != 0 {
		t.Errorf("web kept %d pages (want %d), website kept %v, skipped %d (want 0)", n, pages, kept, skipped)
	}
}

// Every lens that skips hosted URLs is a registered lens.
func TestSkipHostedURLsNamesLenses(t *testing.T) {
	for _, name := range loadLensRules().SkipHostedURLs {
		if _, ok := SubjectLensNamed(name); !ok {
			t.Errorf("lens.json skip_hosted_urls names an unknown lens %q", name)
		}
	}
	for _, reader := range []string{LensWeb, LensExposure, LensServices, LensAccounts, LensCoverage, LensChanges} {
		if skipsHostedURLs(reader) {
			t.Errorf("%s reads URLs but skips them", reader)
		}
	}
}
