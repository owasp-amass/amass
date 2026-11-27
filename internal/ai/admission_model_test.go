// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"testing"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func admissionRequest(strength string) *et.AdmissionRequest {
	return &et.AdmissionRequest{
		Entity:     &dbt.Entity{ID: "1", Asset: &oamdns.FQDN{Name: "owasp-arts.org"}},
		For:        &dbt.Entity{ID: "2", Asset: &oamorg.Organization{ID: "owasp:1", Name: "OWASP Foundation"}},
		Via:        "Horizontals",
		Confidence: 60,
		Evidence: []et.AdmissionEvidence{{Signal: "shared-favicon", Strength: strength,
			Cites: []*dbt.Entity{{ID: "3", Asset: &oamdns.FQDN{Name: "www.owasp.org"}}}}},
	}
}

func TestAdmissionModelTakesOnlyOpenCases(t *testing.T) {
	a := &AdmissionModel{Model: &replyModel{}, ModelID: "test"}
	if _, ok, _ := a.Decide(context.Background(), nil, admissionRequest(et.StrengthStrong)); ok {
		t.Error("strong evidence is the evidence rule's to decide")
	}
	req := admissionRequest(et.StrengthSupporting)
	req.For = nil
	if _, ok, _ := a.Decide(context.Background(), nil, req); ok {
		t.Error("a request for no organization was taken")
	}
	v, ok, err := a.Decide(context.Background(), nil, admissionRequest(et.StrengthSupporting))
	if err != nil || !ok || v.Outcome != et.Pending || v.Later == nil {
		t.Fatalf("supporting evidence: %+v, %v, %v", v, ok, err)
	}
}

func TestAdmissionModelDecides(t *testing.T) {
	for _, tc := range []struct {
		reply               string
		outcome, conclusion et.AdmissionOutcome
		reason              string
	}{
		{`{"decision":"admit","confidence":0.9,"reason":"same favicon as www.owasp.org"}`, et.Admitted,
			et.Admitted, "same favicon"},
		{`{"decision":"admit","confidence":0.6,"reason":"weak"}`, et.Rejected, et.Admitted, "below 80"},
		{`{"decision":"reject","confidence":0.8,"reason":"a template icon"}`, et.Rejected, et.Rejected, "template"},
	} {
		m := &replyModel{reply: tc.reply}
		a := &AdmissionModel{Model: m, ModelID: "test"}
		v, _, _ := a.Decide(context.Background(), nil, admissionRequest(et.StrengthSupporting))
		got, err := v.Later(context.Background())
		if err != nil || got.Outcome != tc.outcome || got.Conclusion != tc.conclusion ||
			!strings.Contains(got.Rationale, tc.reason) {
			t.Errorf("%s: %+v, %v", tc.reply, got, err)
		}

		asked := m.asked[len(m.asked)-1].Text
		for _, want := range []string{"Organization: OWASP Foundation", "Asset: FQDN owasp-arts.org",
			"shared-favicon (supporting): Shared favicon", "Seen on: FQDN www.owasp.org"} {
			if !strings.Contains(asked, want) {
				t.Errorf("the model was not told %q:\n%s", want, asked)
			}
		}
	}

	// the expansion policy's confidence, when higher, is the bar
	req := admissionRequest(et.StrengthSupporting)
	req.PolicyConfidence = 95
	a := &AdmissionModel{Model: &replyModel{reply: `{"decision":"admit","confidence":0.9,"reason":"same favicon"}`},
		ModelID: "test"}
	v, _, _ := a.Decide(context.Background(), nil, req)
	if got, _ := v.Later(context.Background()); got.Outcome != et.Rejected || !strings.Contains(got.Rationale, "below 95") {
		t.Errorf("a policy asking for 95: %+v", got)
	}

	a = &AdmissionModel{Model: &replyModel{reply: "not json"}, ModelID: "test"}
	v, _, _ = a.Decide(context.Background(), nil, admissionRequest(et.StrengthSupporting))
	if _, err := v.Later(context.Background()); err == nil {
		t.Error("an unreadable reply must be an error, which leaves the asset out")
	}
}
