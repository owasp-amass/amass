// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestOrgNameKey(t *testing.T) {
	for name, want := range map[string]string{
		"Google Trust Services LLC":              "google trust services",
		"Acme, Inc.":                             "acme",
		"ab&c enterprises, llc":                  "ab&c enterprises",
		"Société Exemple S.A.":                   "societe exemple",
		"Proofpoint Pty Ltd":                     "proofpoint",
		"Acme & Acme":                            "acme and acme",
		"The Trustees of Utica University":       "utica university",
		"Acme Intl Mfg Co":                       "acme international manufacturing",
		"  Acme   (Holdings)  ":                  "acme holdings",
		"GlobalSign nv-sa":                       "globalsign",
		"Amazon.com, Inc.":                       "amazon.com",
		"Canva Pty Ltd":                          "canva",
		"DigiCert Inc":                           "digicert",
		"widget & gadget co.":                    "widget and gadget",
		"utica products plc":                     "utica products",
		"utica & sons plumbing":                  "utica and sons plumbing",
		"Trustees of SUNY Polytechnic Institute": "suny polytechnic institute",
		"The Utica Outfitters Inc":               "the utica outfitters",
		"S.A.":                                   "s.a",
		"Inc.":                                   "inc",
		"The Trustees of":                        "the trustees of",
		"":                                       "",
		" ,. ":                                   "",
	} {
		if got := OrgNameKey(name); got != want {
			t.Errorf("OrgNameKey(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestIsOrgLegalForm(t *testing.T) {
	for w, want := range map[string]bool{"Inc.": true, "LLC": true, "pty ltd": true, "S.A.": true, "Acme": false,
		"university": false} {
		if got := IsOrgLegalForm(w); got != want {
			t.Errorf("IsOrgLegalForm(%q) = %v, want %v", w, got, want)
		}
	}
	if !IsOrgGenericWord("services") || IsOrgGenericWord("utica") || len(OrgGenericWords()) == 0 {
		t.Error("the generic words were not loaded")
	}
}

// TestOrgNamePairs checks OrgNameMatch against the labeled pairs, both ways.
func TestOrgNamePairs(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "org_name_pairs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		About string `json:"_about"`
		Pairs []struct {
			A, B, Want string
		} `json:"pairs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Pairs) < 20 {
		t.Fatalf("only %d labeled pairs", len(doc.Pairs))
	}

	for _, p := range doc.Pairs {
		for _, order := range [][2]string{{p.A, p.B}, {p.B, p.A}} {
			exact, near := OrgNameMatch(order[0], order[1])
			got := "none"
			switch {
			case exact:
				got = "exact"
			case near:
				got = "near"
			}
			if got != p.Want {
				t.Errorf("OrgNameMatch(%q, %q) = %s, want %s (keys %q, %q)", order[0], order[1], got, p.Want,
					OrgNameKey(order[0]), OrgNameKey(order[1]))
			}
			if same := SameOrgName(order[0], order[1]); same != (p.Want != "none") {
				t.Errorf("SameOrgName(%q, %q) = %v for a %s match", order[0], order[1], same, p.Want)
			}
		}
	}
}

func TestOrgNameMatchesLabel(t *testing.T) {
	for _, c := range []struct {
		name, label string
		want        bool
	}{
		{"owasp", "owasp", true},
		{"utica products usa service company", "uticaproductsus", true},
		{"open worldwide application security project", "owasp", true},
		{"utica products corporation", "upc", true},
		{"utica valley community college", "uvcc", true},
		{"utica university", "utica", true},
		{"salesforce", "uticaproductsus", false},
		// A generic leading word alone does not spell a label.
		{"global products", "global", false},
		// A short name only matches a label it equals.
		{"ups", "upsolutions", false},
		{"utica institute of technology", "uit", true},
		{"utica products", "uproducts", true},
		{"utica products", "products", false},
	} {
		if got := OrgNameMatchesLabel(strings.Fields(c.name), c.label); got != c.want {
			t.Errorf("OrgNameMatchesLabel(%q, %q) = %v, want %v", c.name, c.label, got, c.want)
		}
	}
}

// Names are compared from many plugin handlers at once, so the key must be
// safe to compute concurrently (a shared accent-folding transformer once
// panicked with slice bounds out of range).
func TestOrgNameKeyIsSafeForConcurrentUse(t *testing.T) {
	names := []string{"Société Exemple S.A.", "Example Packard Enterprise", "Café Müller GmbH", "SUNY Polytechnic Institute"}
	want := make([]string, len(names))
	for i, n := range names {
		want[i] = OrgNameKey(n)
	}

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				n := i % len(names)
				if got := OrgNameKey(names[n]); got != want[n] {
					t.Errorf("OrgNameKey(%q) = %q, want %q", names[n], got, want[n])
					return
				}
				_ = PlainText(names[n])
			}
		}()
	}
	wg.Wait()
}
