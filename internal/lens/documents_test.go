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
		{"u-plan", "https://www.owasp.org/it/plan.pdf"},
		{"u-copy", "https://www.owasp.org/old/plan.pdf"},
	} {
		asset(u.id, "URL", u.raw, map[string]any{"url": u.raw})
		link(u.id, "domain", "www.owasp.org")
	}
	asset("f-plan", "File", "https://www.owasp.org/it/plan.pdf", map[string]any{
		"url": "https://www.owasp.org/it/plan.pdf", "name": "plan.pdf", "type": "application/pdf", "size": 48213})
	asset("f-copy", "File", "https://www.owasp.org/old/plan.pdf", map[string]any{
		"url": "https://www.owasp.org/old/plan.pdf", "name": "plan.pdf", "type": "application/pdf"})
	link("u-plan", "file", "f-plan")
	link("u-copy", "file", "f-copy")
	g.EvidenceByID["f-plan"] = []graph.Evidence{
		graphtest.SimpleProp(propDocTitle, "IT Strategic Plan"),
		graphtest.SimpleProp(propDocCreated, "2024-01-02T03:04:05Z"),
		graphtest.SimpleProp(propDocRetrievedFrom, "https://web.archive.org/web/2id_/https://www.owasp.org/it/plan.pdf"),
		graphtest.SimpleProp(propDocImageCamera, "word/media/image1.jpeg: Canon EOS 5D Mark IV"),
	}

	asset("p-jsmith", "Person", "John Smith", map[string]any{"full_name": "John Smith"})
	asset("prod-word", "Product", "cpe:2.3:a:microsoft:word", map[string]any{
		"unique_id": "cpe:2.3:a:microsoft:word", "product_name": "Microsoft Word"})
	asset("acct-jsmith", "Account", "directory:owasp.org:jsmith", map[string]any{
		"unique_id": "directory:owasp.org:jsmith", "account_type": "directory", "username": "jsmith"})
	asset("id-email", "Identifier", "email:jsmith@owasp.org", map[string]any{
		"unique_id": "email:jsmith@owasp.org", "id": "jsmith@owasp.org", "id_type": "email"})
	asset("vpn.owasp.org", "FQDN", "vpn.owasp.org", map[string]any{"name": "vpn.owasp.org"})
	asset("id-hash", "Identifier", "file_sha256:abc", map[string]any{
		"unique_id": "file_sha256:abc", "id": "abc", "id_type": "file_sha256"})

	// an embedded photo's EXIF: where it was taken, by whom, with which body
	asset("geo-hall", "GeoLocation", "42.818900,-75.535100", map[string]any{
		"latitude": 42.8189, "longitude": -75.5351, "uncertainty": 12.5})
	asset("p-jdoe", "Person", "Jane Doe", map[string]any{"full_name": "Jane Doe"})
	asset("id-serial", "Identifier", "serial:canon:032021001234", map[string]any{
		"unique_id": "serial:canon:032021001234", "id": "032021001234", "id_type": "serial"})
	link("f-plan", "contains", "geo-hall")
	link("f-plan", "contains", "p-jdoe")
	link("f-plan", "contains", "id-serial")

	link("f-plan", "author", "p-jsmith")
	link("f-plan", "created_with", "prod-word")
	link("f-plan", "contains", "acct-jsmith")
	link("f-plan", "contains", "id-email")
	link("f-plan", "contains", "vpn.owasp.org")
	link("f-plan", "fingerprint", "id-hash")
	link("f-copy", "fingerprint", "id-hash")

	r, err := FindDocuments(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if r.Total != 2 || r.ByType["application/pdf"] != 2 || r.Archived != 1 {
		t.Fatalf("total %d, by type %v, archived %d", r.Total, r.ByType, r.Archived)
	}
	top := r.Documents[0]
	if top.URL != "https://www.owasp.org/it/plan.pdf" {
		t.Fatalf("the most revealing document is not first: %+v", r.Documents)
	}
	if top.Title != "IT Strategic Plan" || top.Size != 48213 || !top.Archived {
		t.Errorf("document %+v", top)
	}
	if !slices.Equal(top.Accounts, []string{"jsmith"}) || !slices.Equal(top.Software, []string{"Microsoft Word"}) ||
		len(top.Authors) != 1 {
		t.Errorf("accounts %v, software %v, authors %v", top.Accounts, top.Software, top.Authors)
	}
	if !slices.Equal(top.Emails, []string{"jsmith@owasp.org"}) || !slices.Equal(top.Names, []string{"vpn.owasp.org"}) {
		t.Errorf("emails %v, names %v", top.Emails, top.Names)
	}
	if !slices.Equal(top.Copies, []string{"https://www.owasp.org/old/plan.pdf"}) {
		t.Errorf("copies %v", top.Copies)
	}
	if !slices.Equal(top.Places, []string{"42.818900,-75.535100 ±12 m"}) ||
		!slices.Equal(top.Photographers, []string{"Jane Doe"}) ||
		!slices.Equal(top.Cameras, []string{"Canon EOS 5D Mark IV", "serial 032021001234"}) {
		t.Errorf("places %v, photographers %v, cameras %v", top.Places, top.Photographers, top.Cameras)
	}
	if top.Mentions["Identifier"] != 1 {
		t.Errorf("a camera serial is not a mention: %v", top.Mentions)
	}
	if r.Accounts["jsmith"] != 1 || r.Software["Microsoft Word"] != 1 {
		t.Errorf("rollups: accounts %v, software %v", r.Accounts, r.Software)
	}

	text := r.Text()
	for _, want := range []string{"Documents published by", "User accounts the documents reveal", "jsmith",
		"IT Strategic Plan", "archive copy", "same file at", "Places recorded in embedded photos",
		"photo locations: 42.818900,-75.535100", "photographers: Jane Doe"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

// With no stored document the report says so.
func TestFindDocumentsEmpty(t *testing.T) {
	g := graphtest.VendorFixture()
	r, err := FindDocuments(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 0 || !strings.Contains(r.Text(), "No document is stored") {
		t.Errorf("empty report: %+v\n%s", r, r.Text())
	}
}
