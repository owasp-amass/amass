// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"net/http"
	"slices"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
)

var zeroTime time.Time

func contentFilter(k, v string) dbt.ContentFilters { return dbt.ContentFilters{k: v} }

// accountPDF's title holds the author's own file path, and its text names
// the author's email address and another user's home directory.
const accountPDF = "%PDF-1.4\n1 0 obj\n<< /Author (John Smith) /Producer (Acme PDF 2.1) " +
	`/Title (C:\\Users\\jsmith\\Documents\\plan.docx) ` +
	"/CreationDate (D:20240102030405Z) >>\nendobj\n2 0 obj\n<< /Length 90 >>\nstream\n" +
	`BT (Questions: jsmith@example.com. Template from /home/mdoe/templates) Tj ET` +
	"\nendstream\nendobj\ntrailer\n<< /Info 1 0 R >>\n%%EOF\n"

// Usernames in the metadata and the text become directory Accounts of the
// publishing domain, linked from the File; the one the author's name spells
// is tied to that Person, and to the email address the document holds.
func TestAccountLeads(t *testing.T) {
	f := newFixture(t, http.StatusOK, accountPDF)
	raw := "https://www.example.com/plans/plan.pdf"
	if err := f.d.check(f.event(t, raw)); err != nil {
		t.Fatal(err)
	}
	fent := f.file(t, raw)
	if fent == nil {
		t.Fatal("no File stored")
	}

	got := neighbors(t, f, fent, "contains")
	for _, want := range []string{"directory:example.com:jsmith", "directory:example.com:mdoe"} {
		if !slices.Contains(got, want) {
			t.Errorf("contains %v, missing %s", got, want)
		}
	}

	accts, err := f.sess.DB().FindEntitiesByContent(t.Context(), "Account", zeroTime, 0,
		contentFilter("unique_id", "directory:example.com:jsmith"))
	if err != nil || len(accts) != 1 {
		t.Fatalf("account lookup %v, %v", accts, err)
	}
	if users := neighbors(t, f, accts[0], "user"); len(users) != 1 {
		t.Errorf("jsmith user edges %v, want John Smith", users)
	}
	if ids := neighbors(t, f, accts[0], "id"); !slices.Equal(ids, []string{"email:jsmith@example.com"}) {
		t.Errorf("jsmith id edges %v", ids)
	}

	mdoe, _ := f.sess.DB().FindEntitiesByContent(t.Context(), "Account", zeroTime, 0,
		contentFilter("unique_id", "directory:example.com:mdoe"))
	if len(mdoe) != 1 || len(neighbors(t, f, mdoe[0], "user")) != 0 {
		t.Error("mdoe was tied to a person the document does not name")
	}

	if !slices.Contains(f.disp.Names(), "directory:example.com:jsmith") {
		t.Errorf("account not dispatched: %v", f.disp.Names())
	}
}

func TestUsernameSpells(t *testing.T) {
	for _, u := range []string{"jsmith", "JSmith", "john.smith", "smith_j", "smithjohn", "j-smith"} {
		if !usernameSpells(u, "John", "Smith") {
			t.Errorf("%q spells John Smith", u)
		}
	}
	for _, u := range []string{"smith", "john", "jsmith2", "jdoe", "admin"} {
		if usernameSpells(u, "John", "Smith") {
			t.Errorf("%q does not spell John Smith", u)
		}
	}
	if usernameSpells("o.brien", "Mary", "") {
		t.Error("no family name, no match")
	}
	if !usernameSpells("mobrien", "Mary", "O'Brien") {
		t.Error("punctuation in a name is dropped")
	}
}
