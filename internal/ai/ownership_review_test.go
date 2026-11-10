// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// scriptedModel replies with each text in turn.
type scriptedModel struct {
	replies []string
	calls   int
}

func (m *scriptedModel) Generate(_ context.Context, _ []Message, _ []ToolSpec) (Response, error) {
	reply := m.replies[min(m.calls, len(m.replies)-1)]
	m.calls++
	return Response{Text: reply}, nil
}

func alumniProposal(t *testing.T) OwnershipProposal {
	t.Helper()

	ps := OwnershipProposals(gapReport(t))
	if len(ps) != 1 || len(ps[0].Witness) == 0 {
		t.Fatalf("proposals = %+v", ps)
	}

	return ps[0]
}

func TestAdviceIsVerifiedAgainstTheProposalEvidence(t *testing.T) {
	p := alumniProposal(t)
	m := &scriptedModel{replies: []string{
		"RECOMMENDATION: approve\nThe registrant of colgatealumni.org shares the phone of Colgate University [E99].",
		"<think>checking</think>RECOMMENDATION: approve\nThe registrant shares the organization's phone and " +
			"address [E1, E2]. Colgate University is the subject of the proposal [E1].",
	}}

	adv, err := (Agent{Model: m}).AdviseOwnership(context.Background(), p, "qwen3:8b")
	if err != nil {
		t.Fatal(err)
	}
	if !adv.Verified || adv.Recommendation != AdviseApprove || m.calls != 2 {
		t.Fatalf("advice = %+v after %d calls", adv, m.calls)
	}
	if strings.Contains(adv.Rationale, "RECOMMENDATION") {
		t.Errorf("rationale kept the recommendation line: %q", adv.Rationale)
	}
}

func TestUnverifiedAdviceIsNotARecommendation(t *testing.T) {
	m := &scriptedModel{replies: []string{"I think so.", "Approve it, it is obviously theirs."}}
	adv, err := (Agent{Model: m}).AdviseOwnership(context.Background(), alumniProposal(t), "qwen3:8b")
	if err != nil {
		t.Fatal(err)
	}
	if adv.Verified || adv.Recommendation != AdviseUnsure || len(adv.Problems) == 0 {
		t.Errorf("advice = %+v", adv)
	}
}

func TestAdviceIsJournaledButNeverDecides(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	p := alumniProposal(t)
	if _, err := j.SubmitOwnership([]OwnershipProposal{p}); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordAdvice(OwnershipAdvice{ProposalID: p.ID, Recommendation: AdviseApprove, Verified: true,
		Rationale: "Shared registrant details [E1].", Model: "qwen3:8b"}); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordAdvice(OwnershipAdvice{ProposalID: p.ID, Recommendation: "write it", Model: "x"}); err == nil {
		t.Error("an invalid recommendation was recorded")
	}

	entries, err := j.OwnershipEntries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %+v, %v", entries, err)
	}

	e := entries[0]
	if e.Status != ProposalPending || e.Advice == nil || e.Advice.Recommendation != AdviseApprove {
		t.Errorf("entry = %+v", e)
	}
	if _, ok := OwnershipLabel(e); ok {
		t.Error("advice became a training label")
	}
	if text := FormatOwnershipEntries(entries); !strings.Contains(text, "advice from qwen3:8b: approve.") {
		t.Errorf("listing lacks the advice:\n%s", text)
	}
}

func TestEvidenceLinesParseForOlderProposals(t *testing.T) {
	w, ok := parseEvidenceLine("FQDN www.example.com --port 443/tcp--> Service 1a2b")
	if !ok || w.FromType != "FQDN" || w.From != "www.example.com" || w.Label != "port" || w.Detail != "443/tcp" ||
		w.ToType != "Service" || w.To != "1a2b" {
		t.Errorf("parsed = %+v, %v", w, ok)
	}

	p := alumniProposal(t)
	p.Witness = nil
	if b := proposalBundle(p); len(b.Items) != len(p.Evidence) {
		t.Errorf("bundle from evidence lines has %d items, want %d", len(b.Items), len(p.Evidence))
	}
}
