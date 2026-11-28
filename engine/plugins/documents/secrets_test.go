// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

// A credential in a document's text is recorded as it is read, linked from
// the File by discloses: the secret by its kind and hash, never its value,
// and the AWS access key ID in full.
func TestDocumentTextDisclosures(t *testing.T) {
	token := "ghp_" + strings.Repeat("Q7mZ2pX9vB4kL8nR3tW6yC1dF5gH0jS", 2)[:36]
	doc := ooxmlDoc(t, "Jane Q. Doe", "Microsoft Office Word", "16.0000", "Example Corp",
		"deploy with "+token+" and the key ASIAY34FZKBOKMUTVV7A")
	f := newFixture(t, http.StatusOK, doc)
	raw := "https://www.example.com/ops/deploy.docx"
	if err := f.d.check(f.event(t, raw)); err != nil {
		t.Fatal(err)
	}
	fent := f.file(t, raw)
	if fent == nil {
		t.Fatal("no File stored")
	}

	got := neighbors(t, f, fent, "discloses")
	if !slices.ContainsFunc(got, func(k string) bool { return strings.Contains(k, "github_token:") }) ||
		!slices.ContainsFunc(got, func(k string) bool { return strings.Contains(k, "ASIAY34FZKBOKMUTVV7A") }) {
		t.Errorf("discloses %v, want the token and the access key ID", got)
	}
	for _, k := range got {
		if strings.Contains(k, token) {
			t.Errorf("the token's value is stored: %s", k)
		}
	}
}
