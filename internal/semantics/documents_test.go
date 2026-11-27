// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

func TestDocumentRules(t *testing.T) {
	r := Documents()
	if r.MaxBytes <= 0 {
		t.Fatalf("max_bytes = %d", r.MaxBytes)
	}

	for p, want := range map[string]string{
		"/reports/Annual-Report.PDF": "pdf",
		"/forms/apply.docx":          "ooxml",
		"/budget/fy26.xlsx":          "ooxml",
		"/index.html":                "",
		"/doc.pdf/view":              "",
	} {
		got, ok := r.DocumentFor(p)
		if (want == "") == ok || got.Format != want {
			t.Errorf("DocumentFor(%q) = %+v, %v; want format %q", p, got, ok, want)
		}
	}
}

// Default author values name no one and are told apart without case.
func TestPlaceholderAuthors(t *testing.T) {
	r := Documents()
	for _, a := range []string{"Microsoft Office User", " windows user ", "Administrator"} {
		if !r.IsPlaceholderAuthor(a) {
			t.Errorf("%q is a placeholder author", a)
		}
	}
	if r.IsPlaceholderAuthor("Jane Doe") {
		t.Error("a real name is not a placeholder")
	}
}

func TestPlaceholderCompanies(t *testing.T) {
	r := Documents()
	for _, c := range []string{"Dell Inc.", "HP", " Home "} {
		if !r.IsPlaceholderCompany(c) {
			t.Errorf("%q is a placeholder company", c)
		}
	}
	if r.IsPlaceholderCompany("Utica University") {
		t.Error("a real organization is not a placeholder")
	}
}
