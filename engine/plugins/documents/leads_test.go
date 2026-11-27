// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// leadPDF names, in its text and a link annotation, an in-scope email
// address, host name and portal URL, and an out-of-scope vendor URL.
const leadPDF = "%PDF-1.4\n1 0 obj\n<< /Author (Jane Q. Doe) /Creator (Microsoft Word) /Producer (Acme PDF 2.1) " +
	"/CreationDate (D:20240102030405Z) >>\nendobj\n2 0 obj\n<< /Type /Annot /Subtype /Link /A << /S /URI " +
	"/URI (https://portal.example.com/login) >> >>\nendobj\n3 0 obj\n<< /Length 120 >>\nstream\n" +
	"BT (Help desk: helpdesk@example.com, VPN at vpn.example.com, " +
	"forms at https://vendor.other.net/forms) Tj ET\nendstream\nendobj\ntrailer\n<< /Info 1 0 R >>\n%%EOF\n"

func neighbors(t *testing.T, f *fixture, from *dbt.Entity, label string) []string {
	t.Helper()
	ctx := context.Background()
	// the repository reports "zero edges found" as an error; none is an answer
	edges, _ := f.sess.DB().OutgoingEdges(ctx, from, time.Time{}, label)
	var keys []string
	for _, edge := range edges {
		if ent, err := f.sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil {
			keys = append(keys, ent.Asset.Key())
		}
	}
	slices.Sort(keys)
	return keys
}

// What the document's content names is linked from the File by contains;
// in-scope names and URLs are dispatched as leads, the out-of-scope vendor
// URL is recorded but not dispatched.
func TestContentLeads(t *testing.T) {
	f := newFixture(t, http.StatusOK, leadPDF)
	raw := "https://www.example.com/files/it-guide.pdf"
	if err := f.d.check(f.event(t, raw)); err != nil {
		t.Fatal(err)
	}
	fent := f.file(t, raw)
	if fent == nil {
		t.Fatal("no File stored")
	}

	got := neighbors(t, f, fent, "contains")
	for _, want := range []string{"email:helpdesk@example.com", "vpn.example.com", "portal.example.com",
		"https://portal.example.com/login", "https://vendor.other.net/forms", "vendor.other.net"} {
		if !slices.Contains(got, want) {
			t.Errorf("contains %v, missing %s", got, want)
		}
	}

	names := f.disp.Names()
	for _, want := range []string{"vpn.example.com", "https://portal.example.com/login"} {
		if !slices.Contains(names, want) {
			t.Errorf("dispatched %v, missing %s", names, want)
		}
	}
	for _, not := range []string{"https://vendor.other.net/forms", "vendor.other.net"} {
		if slices.Contains(names, not) {
			t.Errorf("out-of-scope %s was dispatched", not)
		}
	}

	// the software that made it is a Product with its manufacturer
	made := neighbors(t, f, fent, "created_with")
	if !slices.Equal(made, []string{"cpe:2.3:a:microsoft:word"}) {
		t.Errorf("created_with %v", made)
	}
}

// ooxmlDoc builds a Word document with the given core and app properties.
func ooxmlDoc(t *testing.T, creator, app, version, company, text string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, body string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	add("docProps/core.xml", `<cp:coreProperties xmlns:cp="cp" xmlns:dc="dc"><dc:creator>`+creator+
		`</dc:creator></cp:coreProperties>`)
	add("docProps/app.xml", `<Properties><Application>`+app+`</Application><AppVersion>`+version+
		`</AppVersion><Company>`+company+`</Company></Properties>`)
	add("word/document.xml", `<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>`+text+
		`</w:t></w:r></w:p></w:body></w:document>`)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// The metadata's author and company are linked as authors, and the
// versioned application as created_with to its release.
func TestMetadataLeads(t *testing.T) {
	doc := ooxmlDoc(t, "John Smith", "Microsoft Office Word", "16.0000", "Example University", "Annual plan")
	f := newFixture(t, http.StatusOK, doc)
	raw := "https://www.example.com/plans/plan.docx"
	if err := f.d.check(f.event(t, raw)); err != nil {
		t.Fatal(err)
	}
	fent := f.file(t, raw)
	if fent == nil {
		t.Fatal("no File stored")
	}

	var person, organization bool
	ctx := context.Background()
	edges, _ := f.sess.DB().OutgoingEdges(ctx, fent, time.Time{}, "author")
	for _, edge := range edges {
		ent, err := f.sess.DB().FindEntityById(ctx, edge.ToEntity.ID)
		if err != nil {
			continue
		}
		switch a := ent.Asset.(type) {
		case *oamorg.Organization:
			organization = a.Name != ""
		default:
			person = person || a.Key() != ""
		}
	}
	if !person || !organization {
		t.Errorf("author edges: person %v, organization %v (%d edges)", person, organization, len(edges))
	}

	made := neighbors(t, f, fent, "created_with")
	if !slices.Equal(made, []string{"Microsoft Word 16.0000"}) {
		t.Errorf("created_with %v, want the release", made)
	}
	products, err := f.sess.DB().FindEntitiesByContent(ctx, oam.Product, time.Time{}, 0,
		dbt.ContentFilters{"unique_id": "cpe:2.3:a:microsoft:word"})
	if err != nil || len(products) != 1 {
		t.Fatalf("Product lookup %v, %v", products, err)
	}
	if p := products[0].Asset.(*oamplat.Product); p.Name != "Microsoft Word" {
		t.Errorf("Product %+v", p)
	}
	if rel := neighbors(t, f, products[0], "release"); !slices.Equal(rel, []string{"Microsoft Word 16.0000"}) {
		t.Errorf("release %v", rel)
	}
	if mk := neighbors(t, f, products[0], "manufacturer"); len(mk) != 1 {
		t.Errorf("manufacturer %v", mk)
	}
}

// A Company that is a preset, a placeholder, or the vendor of the software
// that made the document names no author.
func TestCompanyNamesAuthor(t *testing.T) {
	rules := semantics.Documents()
	vendors := []string{"Microsoft Corporation"}
	for _, c := range []string{"", "Dell Inc.", "Home", "Microsoft", "Microsoft Corporation", "Redacted for Privacy"} {
		if companyNamesAuthor(rules, c, vendors) {
			t.Errorf("%q named an author", c)
		}
	}
	if !companyNamesAuthor(rules, "Example University", vendors) {
		t.Error("a real organization did not name the author")
	}
}

func TestIPAddressesSkipsSpecialPurpose(t *testing.T) {
	got := ipAddresses("gw 10.0.0.1, dns 8.8.8.8, lo 127.0.0.1, web 192.0.2.10 and 8.8.8.8 again, bad 999.1.1.1")
	var s []string
	for _, a := range got {
		s = append(s, a.String())
	}
	if !slices.Contains(s, "8.8.8.8") || slices.Contains(s, "10.0.0.1") || slices.Contains(s, "127.0.0.1") ||
		len(s) > 2 {
		t.Errorf("addresses %v", s)
	}
}

func TestPhoneNumbers(t *testing.T) {
	got := phoneNumbers("Call (202) 456-1111 or +44 20 7946 0958; ref 2024-01-02, id 12345678901", "US")
	var e164 []string
	for _, p := range got {
		e164 = append(e164, p.E164)
	}
	if !slices.Contains(e164, "+12024561111") || !slices.Contains(e164, "+442079460958") || len(e164) != 2 {
		t.Errorf("phones %v", e164)
	}
}

func TestRegionOf(t *testing.T) {
	for host, want := range map[string]string{"www.example.edu": "US", "www.example.co.uk": "GB",
		"www.example.de": "DE"} {
		if got := regionOf(host); got != want {
			t.Errorf("regionOf(%s) = %s, want %s", host, got, want)
		}
	}
}

// Out of scope, only URLs written with their scheme are taken from the text;
// scheme-less look-alikes ("k.bs", "report.final") are not leads.
func TestSchemelessOutOfScopeIgnored(t *testing.T) {
	doc := ooxmlDoc(t, "", "", "", "",
		"see k.bs and n.it, or portal.example.com/login and https://partner.other.org/x")
	f := newFixture(t, http.StatusOK, doc)
	raw := "https://www.example.com/a.docx"
	if err := f.d.check(f.event(t, raw)); err != nil {
		t.Fatal(err)
	}
	fent := f.file(t, raw)
	if fent == nil {
		t.Fatal("no File stored")
	}

	got := neighbors(t, f, fent, "contains")
	for _, want := range []string{"http://portal.example.com/login", "https://partner.other.org/x"} {
		if !slices.Contains(got, want) {
			t.Errorf("contains %v, missing %s", got, want)
		}
	}
	for _, not := range []string{"k.bs", "n.it", "http://k.bs", "http://n.it"} {
		if slices.Contains(got, not) {
			t.Errorf("noise %s was linked", not)
		}
	}
}

// A URL whose host is a fragment of a name broken across lines is not taken,
// even when written with its scheme.
func TestBrokenHostIgnored(t *testing.T) {
	doc := ooxmlDoc(t, "", "", "", "", "see http://www.examp and https://partner.other.org/x")
	f := newFixture(t, http.StatusOK, doc)
	raw := "https://www.example.com/b.docx"
	if err := f.d.check(f.event(t, raw)); err != nil {
		t.Fatal(err)
	}
	fent := f.file(t, raw)
	if fent == nil {
		t.Fatal("no File stored")
	}
	got := neighbors(t, f, fent, "contains")
	if slices.Contains(got, "http://www.examp") || !slices.Contains(got, "https://partner.other.org/x") {
		t.Errorf("contains %v", got)
	}
}
