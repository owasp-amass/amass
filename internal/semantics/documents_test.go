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
