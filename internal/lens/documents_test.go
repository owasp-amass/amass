// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// The documents lens lists the Files stored from the subject's URLs with who
// and what made them, the accounts they reveal, what they mention, and the
// other URLs serving the same bytes.
func TestFindDocuments(t *testing.T) {
	g := graphtest.VendorFixture()
	if g.EvidenceByID == nil {
		g.EvidenceByID = map[string][]graph.Evidence{}
	}
	asset := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}

	// two URLs on the organization's own name serve the same PDF
	for _, u := range []struct{ id, raw string }{
		{"u-plan", "https://www.colgate.edu/it/plan.pdf"},
		{"u-copy", "https://www.colgate.edu/old/plan.pdf"},
	} {
		asset(u.id, "URL", u.raw, map[string]any{"url": u.raw})
		link(u.id, "domain", "www.colgate.edu")
	}
	asset("f-plan", "File", "https://www.colgate.edu/it/plan.pdf", map[string]any{
		"url": "https://www.colgate.edu/it/plan.pdf", "name": "plan.pdf", "type": "application/pdf", "size": 48213})
	asset("f-copy", "File", "https://www.colgate.edu/old/plan.pdf", map[string]any{
		"url": "https://www.colgate.edu/old/plan.pdf", "name": "plan.pdf", "type": "application/pdf"})
	link("u-plan", "file", "f-plan")
	link("u-copy", "file", "f-copy")
	g.EvidenceByID["f-plan"] = []graph.Evidence{
		graphtest.SimpleProp(propDocTitle, "IT Strategic Plan"),
		graphtest.SimpleProp(propDocCreated, "2024-01-02T03:04:05Z"),
		graphtest.SimpleProp(propDocRetrievedFrom, "https://web.archive.org/web/2id_/https://www.colgate.edu/it/plan.pdf"),
	}

	asset("p-jsmith", "Person", "John Smith", map[string]any{"full_name": "John Smith"})
	asset("prod-word", "Product", "cpe:2.3:a:microsoft:word", map[string]any{
		"unique_id": "cpe:2.3:a:microsoft:word", "product_name": "Microsoft Word"})
	asset("acct-jsmith", "Account", "directory:colgate.edu:jsmith", map[string]any{
		"unique_id": "directory:colgate.edu:jsmith", "account_type": "directory", "username": "jsmith"})
	asset("id-email", "Identifier", "email:jsmith@colgate.edu", map[string]any{
		"unique_id": "email:jsmith@colgate.edu", "id": "jsmith@colgate.edu", "id_type": "email"})
	asset("vpn.colgate.edu", "FQDN", "vpn.colgate.edu", map[string]any{"name": "vpn.colgate.edu"})
	asset("id-hash", "Identifier", "file_sha256:abc", map[string]any{
		"unique_id": "file_sha256:abc", "id": "abc", "id_type": "file_sha256"})

	link("f-plan", "author", "p-jsmith")
	link("f-plan", "created_with", "prod-word")
	link("f-plan", "contains", "acct-jsmith")
	link("f-plan", "contains", "id-email")
	link("f-plan", "contains", "vpn.colgate.edu")
	link("f-plan", "fingerprint", "id-hash")
	link("f-copy", "fingerprint", "id-hash")

	r, err := FindDocuments(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if r.Total != 2 || r.ByType["application/pdf"] != 2 || r.Archived != 1 {
		t.Fatalf("total %d, by type %v, archived %d", r.Total, r.ByType, r.Archived)
	}
	top := r.Documents[0]
	if top.URL != "https://www.colgate.edu/it/plan.pdf" {
		t.Fatalf("the most revealing document is not first: %+v", r.Documents)
	}
	if top.Title != "IT Strategic Plan" || top.Size != 48213 || !top.Archived {
		t.Errorf("document %+v", top)
	}
	if !slices.Equal(top.Accounts, []string{"jsmith"}) || !slices.Equal(top.Software, []string{"Microsoft Word"}) ||
		len(top.Authors) != 1 {
		t.Errorf("accounts %v, software %v, authors %v", top.Accounts, top.Software, top.Authors)
	}
	if !slices.Equal(top.Emails, []string{"jsmith@colgate.edu"}) || !slices.Equal(top.Names, []string{"vpn.colgate.edu"}) {
		t.Errorf("emails %v, names %v", top.Emails, top.Names)
	}
	if !slices.Equal(top.Copies, []string{"https://www.colgate.edu/old/plan.pdf"}) {
		t.Errorf("copies %v", top.Copies)
	}
	if r.Accounts["jsmith"] != 1 || r.Software["Microsoft Word"] != 1 {
		t.Errorf("rollups: accounts %v, software %v", r.Accounts, r.Software)
	}

	text := r.Text()
	for _, want := range []string{"Documents published by", "User accounts the documents reveal", "jsmith",
		"IT Strategic Plan", "archive copy", "same file at"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

// With no stored document the report says so.
func TestFindDocumentsEmpty(t *testing.T) {
	g := graphtest.VendorFixture()
	r, err := FindDocuments(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 0 || !strings.Contains(r.Text(), "No document is stored") {
		t.Errorf("empty report: %+v\n%s", r, r.Text())
	}
}
