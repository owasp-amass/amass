// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"testing"
)

// goodVendorNarrative cites the colgate.edu vendor bundle correctly.
const goodVendorNarrative = "colgate.edu receives mail through mx1.pphosted.com and uses pdns1.ultradns.net as a " +
	"name server [E1, E2]. www.colgate.edu resolves to 151.101.1.1, which AutonomousSystem 54113 announces and " +
	"whose registration names FASTLY [E6, E7, E8, E9]. Its certificate was issued by DigiCert Inc [E3, E4, E5]. " +
	"The domain's registrar contact belongs to EDUCAUSE [E10, E11]."

func vendorBundle(t *testing.T) (Investigation, EvidenceBundle) {
	t.Helper()

	inv, err := vendorAgent(nil).AskQuery(context.Background(),
		thirdPartyQuery("", PlanSubject{Type: "FQDN", Field: "name", Value: "colgate.edu"}, SourceCaller),
		AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	return inv, BuildEvidenceBundle(inv, narrativeMaxItems)
}

func TestVendorAnswersCarryWitnessEdges(t *testing.T) {
	_, b := vendorBundle(t)
	text := b.String()
	for _, want := range []string{
		"FQDN www.colgate.edu --dns_record--> IPAddress 151.101.1.1",
		"AutonomousSystem 54113 --announces--> Netblock 151.101.0.0/16",
		"ContactRecord https://crt.example/issuer --organization--> Organization DigiCert Inc",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("bundle lacks %q:\n%s", want, text)
		}
	}
}

func TestVerifyCitationsAcceptsGroundedProse(t *testing.T) {
	_, b := vendorBundle(t)
	if problems := VerifyCitations(goodVendorNarrative, b); len(problems) != 0 {
		t.Fatalf("grounded prose rejected: %v", problems)
	}
}

// Organization names outside the evidence cannot be recognized in free
// text ("Cloudflare" below passes); hostnames and IP addresses can.
func TestVerifyCitationsRejectsUngroundedProse(t *testing.T) {
	_, b := vendorBundle(t)
	for text, want := range map[string]string{
		"colgate.edu uses several vendors.":                         "has no citation",
		"colgate.edu uses FASTLY [E99].":                            "E99, which is not in the evidence",
		"www.colgate.edu is hosted by FASTLY [E6].":                 "names FASTLY but none of its citations",
		"Cloudflare hosts colgate.edu [E1]. It is fast [E1].":       "",
		"www.cloudflare.com hosts colgate.edu [E1].":                "names www.cloudflare.com, which is not in",
		"colgate.edu also resolves to 192.0.2.9 [E1].":              "names 192.0.2.9, which is not in",
		"www.colgate.edu resolves to 151.101.1.1. [E6] It is [E7].": "",
	} {
		problems := strings.Join(VerifyCitations(text, b), "; ")
		if want == "" && problems != "" {
			t.Errorf("%q: unexpected problems %s", text, problems)
		}
		if want != "" && !strings.Contains(problems, want) {
			t.Errorf("%q: problems %q, want %q", text, problems, want)
		}
	}
}

// "www.colgate.edu" must not also count as a mention of "colgate.edu".
func TestVerifyCitationsMatchesLongestName(t *testing.T) {
	_, b := vendorBundle(t)
	if problems := VerifyCitations("www.colgate.edu resolves to 151.101.1.1 [E6].", b); len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
}

func TestNarrateRetriesThenVerifies(t *testing.T) {
	inv, _ := vendorBundle(t)
	model := &plannerModel{replies: []string{"colgate.edu uses FASTLY.", goodVendorNarrative}}

	n, err := Agent{Model: model}.Narrate(context.Background(), "Which vendors does colgate.edu use?", inv)
	if err != nil {
		t.Fatal(err)
	}
	if !n.Verified || n.Attempts != 2 || len(n.Cited) != 11 {
		t.Fatalf("narrative = %+v, want verified on the second attempt citing 11 items", n)
	}
	if text := NarrativeText(n); !strings.Contains(text, "Evidence:\n  E1: FQDN colgate.edu --dns_record-->") {
		t.Errorf("rendered narrative lacks its evidence:\n%s", text)
	}
}

func TestNarrateRejectsAfterRetry(t *testing.T) {
	inv, _ := vendorBundle(t)
	model := &plannerModel{replies: []string{"Cloudflare hosts everything for colgate.edu."}}

	n, err := Agent{Model: model}.Narrate(context.Background(), "Which vendors does colgate.edu use?", inv)
	if err != nil {
		t.Fatal(err)
	}
	if n.Verified || n.Text != "" || len(n.Rejected) == 0 || NarrativeText(n) != "" {
		t.Fatalf("unverified narrative was accepted: %+v", n)
	}
}

func TestTableRowsCarryWitnessEdges(t *testing.T) {
	g, cat := campusWeb()
	q := Query{Version: QueryVersion, Subject: PlanSubject{Type: "Organization", Name: "Colgate University"},
		Traversal: TraversalExplore, TargetTypes: []string{"URL"}, Direction: "both", Purpose: "connected",
		Lens: LensTable, Columns: []TableColumn{{Type: "IPAddress"}, {Type: "Organization", Role: ColumnController}},
		Source: SourceCaller}

	inv, err := Agent{Runner: ToolRunner{Graph: g, Catalog: cat, Limits: DefaultLimits()}}.AskQuery(
		context.Background(), q, AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	r := inv.TableReport
	if len(r.Witness) != len(r.Rows) {
		t.Fatalf("%d witness lists for %d rows", len(r.Witness), len(r.Rows))
	}

	www := ""
	for i, row := range r.Rows {
		if row[0] == "https://www.colgate.edu" {
			for _, e := range r.Witness[i] {
				www += e.From + " --" + e.Label + "--> " + e.To + "\n"
			}
		}
	}
	for _, want := range []string{"Colgate University --website--> https://www.colgate.edu",
		"www.colgate.edu --dns_record--> 151.101.1.1", "54113 --registration--> FASTLY"} {
		if !strings.Contains(www, want) {
			t.Errorf("www row witness lacks %q:\n%s", want, www)
		}
	}
}

// Live eval: Qwen wrote "colgate.edu relies on ..." citing items about
// www.colgate.edu. The subject comes from the question, so naming it is
// grounded; other assets still need a citation that mentions them.
func TestVerifyCitationsAllowsNamingTheSubject(t *testing.T) {
	_, b := vendorBundle(t)
	if len(b.Subjects) == 0 || b.Subjects[0] != "colgate.edu" {
		t.Fatalf("subjects = %v, want colgate.edu first", b.Subjects)
	}

	text := "colgate.edu depends on FASTLY, which announces the network behind www.colgate.edu [E6, E7, E8, E9]."
	if problems := VerifyCitations(text, b); len(problems) != 0 {
		t.Fatalf("naming the subject was rejected: %v", problems)
	}

	text = "colgate.edu depends on FASTLY [E1]."
	if problems := strings.Join(VerifyCitations(text, b), "; "); !strings.Contains(problems, "names FASTLY") {
		t.Errorf("a vendor without a supporting citation passed: %q", problems)
	}
	if problems := VerifyCitations("colgate.edu uses several providers.", b); len(problems) == 0 {
		t.Error("an uncited sentence about the subject passed")
	}
}
