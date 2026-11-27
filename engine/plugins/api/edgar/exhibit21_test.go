// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package edgar

import (
	"reflect"
	"testing"
)

func TestLatestAnnualReport(t *testing.T) {
	var sub submissions
	sub.Filings.Recent.Form = []string{"8-K", "10-K/A", "10-Q", "10-K", "20-F"}
	sub.Filings.Recent.AccessionNumber = []string{"a1", "a2", "a3", "a4", "a5"}

	if acc, prefix := latestAnnualReport(&sub); acc != "a4" || prefix != "EX-21" {
		t.Fatalf("latestAnnualReport = %q, %q", acc, prefix)
	}

	sub.Filings.Recent.Form = []string{"6-K", "20-F"}
	sub.Filings.Recent.AccessionNumber = []string{"b1", "b2"}
	if acc, prefix := latestAnnualReport(&sub); acc != "b2" || prefix != "EX-8" {
		t.Fatalf("foreign filer: latestAnnualReport = %q, %q", acc, prefix)
	}

	sub.Filings.Recent.Form = []string{"8-K"}
	sub.Filings.Recent.AccessionNumber = []string{"c1"}
	if acc, _ := latestAnnualReport(&sub); acc != "" {
		t.Fatalf("no annual report: got %q", acc)
	}
}

const filingIndex = `<html><body>
<table class="tableFile" summary="Document Format Files">
<tr><th scope="col">Seq</th><th scope="col">Description</th><th scope="col">Document</th>
<th scope="col">Type</th><th scope="col">Size</th></tr>
<tr><td scope="row">1</td><td scope="row">10-K</td>
<td scope="row"><a href="/ix?doc=/Archives/edgar/data/1/000000000123000001/ex-20230930.htm">ex-20230930.htm</a></td>
<td scope="row">10-K</td><td scope="row">100</td></tr>
<tr class="evenRow"><td scope="row">5</td><td scope="row">EX-21.1</td>
<td scope="row"><a href="/Archives/edgar/data/1/000000000123000001/ex-20230930xex211.htm">ex-20230930xex211.htm</a></td>
<td scope="row">EX-21.1</td><td scope="row">10</td></tr>
<tr><td scope="row">6</td><td scope="row">EX-210</td>
<td scope="row"><a href="/Archives/edgar/data/1/000000000123000001/other.htm">other.htm</a></td>
<td scope="row">EX-210</td><td scope="row">10</td></tr>
</table></body></html>`

func TestExhibitDocuments(t *testing.T) {
	got := exhibitDocuments(filingIndex, "EX-21")
	want := []string{"/Archives/edgar/data/1/000000000123000001/ex-20230930xex211.htm"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("exhibitDocuments = %v, want %v", got, want)
	}
	if got := exhibitDocuments(filingIndex, "EX-8"); len(got) != 0 {
		t.Fatalf("EX-8 matched %v", got)
	}
}

func TestParseSubsidiariesTable(t *testing.T) {
	doc := `<html><body>
<p>Exhibit 21.1</p><p>Subsidiaries of Example Corp.*</p>
<table>
<tr><td><b>Name of Subsidiary</b></td><td>&#160;</td><td><b>Jurisdiction of Incorporation</b></td></tr>
<tr><td>Example Operations International Limited</td><td>&#160;</td><td>Ireland</td></tr>
<tr><td>Example Sales, LLC (1)</td><td></td><td>Delaware</td><td>100%</td></tr>
<tr><td>2.</td><td>Example Japan K.K.</td><td>Japan</td></tr>
<tr><td>Example UK Limited</td><td>England and Wales</td></tr>
<tr><td>Example Brasil Ltda.</td><td>Sao Paulo</td></tr>
</table>
<p>* Pursuant to Item 601(b)(21)(ii), other subsidiaries are omitted.</p>
</body></html>`

	got := parseSubsidiaries(doc)
	want := []subsidiary{
		{"Example Operations International Limited", "IE"},
		{"Example Sales, LLC", "US-DE"},
		{"Example Japan K.K.", "JP"},
		{"Example UK Limited", "GB"},
		{"Example Brasil Ltda.", "Sao Paulo"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseSubsidiaries =\n%v\nwant\n%v", got, want)
	}
}

func TestParseSubsidiariesLines(t *testing.T) {
	doc := `SUBSIDIARIES OF THE REGISTRANT

Example Holdings, Inc. (Delaware)
  Example Services LLC - Texas
Example Canada Ltd., Ontario
Example GmbH          Germany
Example Asia Pte. Ltd.
Some heading without a company form
`
	got := parseSubsidiaries(doc)
	want := []subsidiary{
		{"Example Holdings, Inc.", "US-DE"},
		{"Example Services LLC", "US-TX"},
		{"Example Canada Ltd.", "CA-ON"},
		{"Example GmbH", "DE"},
		{"Example Asia Pte. Ltd.", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseSubsidiaries =\n%v\nwant\n%v", got, want)
	}
}

func TestParseSubsidiariesParagraphs(t *testing.T) {
	doc := `<html><body><div>LIST OF SUBSIDIARIES</div>
<p>Example Netherlands B.V. (the Netherlands)</p>
<p>Example Australia Pty Ltd<br>Example France SAS (France)</p>
</body></html>`

	got := parseSubsidiaries(doc)
	want := []subsidiary{
		{"Example Netherlands B.V.", "NL"},
		{"Example Australia Pty Ltd", ""},
		{"Example France SAS", "FR"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseSubsidiaries =\n%v\nwant\n%v", got, want)
	}
}

func TestResolveJurisdiction(t *testing.T) {
	cases := map[string]string{
		"Delaware":                             "US-DE",
		"a Delaware limited liability company": "US-DE",
		"Cayman Islands":                       "KY",
		"England & Wales":                      "GB",
	}
	for in, want := range cases {
		if got, ok := resolveJurisdiction(in); !ok || got != want {
			t.Errorf("resolveJurisdiction(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	if _, ok := resolveJurisdiction("100%"); ok {
		t.Error("an ownership share resolved as a jurisdiction")
	}
}
