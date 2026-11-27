// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// goodVendorNarrative cites the owasp.org vendor bundle correctly.
const goodVendorNarrative = "owasp.org receives mail through mx1.pphosted.com and uses pdns1.ultradns.net as a " +
	"name server [E1, E2]. www.owasp.org resolves to 151.101.1.1, which AutonomousSystem 54113 announces and " +
	"whose registration names FASTLY [E6, E7, E8, E9]. Its certificate was issued by DigiCert Inc [E3, E4, E5]. " +
	"The domain's registrar contact belongs to EDUCAUSE [E10, E11]."

func vendorBundle(t *testing.T) (Investigation, review.EvidenceBundle) {
	t.Helper()

	inv, err := vendorAgent(nil).AskQuery(context.Background(),
		thirdPartyQuery("", PlanSubject{Type: "FQDN", Field: "name", Value: "owasp.org"}, SourceCaller),
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
		"FQDN www.owasp.org --dns_record--> IPAddress 151.101.1.1",
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
		"owasp.org uses several vendors.":                         "has no citation",
		"owasp.org uses FASTLY [E99].":                            "E99, which is not in the evidence",
		"www.owasp.org is hosted by FASTLY [E6].":                 "names FASTLY but none of its citations",
		"Cloudflare hosts owasp.org [E1]. It is fast [E1].":       "",
		"www.cloudflare.com hosts owasp.org [E1].":                "names www.cloudflare.com, which is not in",
		"owasp.org also resolves to 192.0.2.9 [E1].":              "names 192.0.2.9, which is not in",
		"www.owasp.org resolves to 151.101.1.1. [E6] It is [E7].": "",
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

// "www.owasp.org" must not also count as a mention of "owasp.org".
func TestVerifyCitationsMatchesLongestName(t *testing.T) {
	_, b := vendorBundle(t)
	if problems := VerifyCitations("www.owasp.org resolves to 151.101.1.1 [E6].", b); len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
}

func TestNarrateRetriesThenVerifies(t *testing.T) {
	inv, _ := vendorBundle(t)
	model := &plannerModel{replies: []string{"owasp.org uses FASTLY.", goodVendorNarrative}}

	n, err := Agent{Model: model}.Narrate(context.Background(), "Which vendors does owasp.org use?", inv)
	if err != nil {
		t.Fatal(err)
	}
	if !n.Verified || n.Attempts != 2 || len(n.Cited) != 11 {
		t.Fatalf("narrative = %+v, want verified on the second attempt citing 11 items", n)
	}
	if text := NarrativeText(n); !strings.Contains(text, "Evidence:\n  E1: FQDN owasp.org --dns_record-->") {
		t.Errorf("rendered narrative lacks its evidence:\n%s", text)
	}
}

func TestNarrateRejectsAfterRetry(t *testing.T) {
	inv, _ := vendorBundle(t)
	model := &plannerModel{replies: []string{"Cloudflare hosts everything for owasp.org."}}

	n, err := Agent{Model: model}.Narrate(context.Background(), "Which vendors does owasp.org use?", inv)
	if err != nil {
		t.Fatal(err)
	}
	if n.Verified || n.Text != "" || len(n.Rejected) == 0 || NarrativeText(n) != "" {
		t.Fatalf("unverified narrative was accepted: %+v", n)
	}
}

func TestTableRowsCarryWitnessEdges(t *testing.T) {
	g, cat := graphtest.CampusWeb()
	q := Query{Version: QueryVersion, Subject: PlanSubject{Type: "Organization", Name: "OWASP Foundation"},
		Traversal: TraversalExplore, TargetTypes: []string{"URL"}, Direction: "both", Purpose: "connected",
		Lens: lens.LensTable, Columns: []lens.TableColumn{{Type: "IPAddress"}, {Type: "Organization", Role: lens.ColumnController}},
		Source: SourceCaller}

	inv, err := Agent{Runner: ToolRunner{Graph: g, Catalog: cat, Limits: graph.DefaultLimits()}}.AskQuery(
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
		if row[0] == "https://www.owasp.org" {
			for _, e := range r.Witness[i] {
				www += e.From + " --" + e.Label + "--> " + e.To + "\n"
			}
		}
	}
	for _, want := range []string{"OWASP Foundation --website--> https://www.owasp.org",
		"www.owasp.org --dns_record--> 151.101.1.1", "54113 --registration--> FASTLY"} {
		if !strings.Contains(www, want) {
			t.Errorf("www row witness lacks %q:\n%s", want, www)
		}
	}
}

// Live eval: Qwen wrote "owasp.org relies on ..." citing items about
// www.owasp.org. The subject comes from the question, so naming it is
// grounded; other assets still need a citation that mentions them.
func TestVerifyCitationsAllowsNamingTheSubject(t *testing.T) {
	_, b := vendorBundle(t)
	if len(b.Subjects) == 0 || b.Subjects[0] != "owasp.org" {
		t.Fatalf("subjects = %v, want owasp.org first", b.Subjects)
	}

	text := "owasp.org depends on FASTLY, which announces the network behind www.owasp.org [E6, E7, E8, E9]."
	if problems := VerifyCitations(text, b); len(problems) != 0 {
		t.Fatalf("naming the subject was rejected: %v", problems)
	}

	text = "owasp.org depends on FASTLY [E1]."
	if problems := strings.Join(VerifyCitations(text, b), "; "); !strings.Contains(problems, "names FASTLY") {
		t.Errorf("a vendor without a supporting citation passed: %q", problems)
	}
	if problems := VerifyCitations("owasp.org uses several providers.", b); len(problems) == 0 {
		t.Error("an uncited sentence about the subject passed")
	}
}
