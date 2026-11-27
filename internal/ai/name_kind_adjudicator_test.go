// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

func TestNameKindFeatures(t *testing.T) {
	f := NameKindFeatures("MarkMonitor, Inc.", "person", "ContactRecord",
		[]string{"the legal form inc", "an organization is stored under the name"})
	for _, k := range []string{"rule:legal_form", "rule:stored_organization", "shape:comma", "field:person",
		"record:ContactRecord"} {
		if f[k] != 1 {
			t.Errorf("%s missing: %v", k, f)
		}
	}
	if p := NameKindFeatures("Sarah Church", "author", "File", []string{"church is also a family name"}); p["shape:parses_as_person"] != 1 || p["rule:family_name_form"] != 1 || p["field:author"] != 1 {
		t.Errorf("person-like name: %v", p)
	}
}

// namesDecided records n name proposals and people's decisions on them, each
// with the several pieces of evidence real names carry (one alone cannot
// reach the 0.90 bar under the trainer's regularization): organizations with
// a legal form, a stored organization and the record's organization; people
// with a middle initial and an email that spells the name.
func namesDecided(t *testing.T, j *review.Journal, n int) {
	t.Helper()
	applier := &fakeNameApplier{}
	for i := 0; i < n; i++ {
		// letters only, so no name carries digits a test question lacks
		w := string(rune('a'+i/26)) + string(rune('a'+i%26))
		name, reasons, kind := "Pat Q Lee"+w, personReasons, review.NameKindPerson
		if i%2 == 0 {
			name, reasons, kind = "Acme"+w+" LLC", orgReasons, review.NameKindOrganization
		}
		p := review.NameKindProposal{ID: review.NameKindProposalID("rec", "person", name), RecordID: "rec",
			RecordType: "ContactRecord", Label: "person", Name: name, Reasons: reasons}
		if _, err := j.SubmitNameKinds([]review.NameKindProposal{p}); err != nil {
			t.Fatal(err)
		}
		if _, err := review.ApplyNameKind(context.Background(), applier, j, p.ID, kind, "jeff", 100, ""); err != nil {
			t.Fatal(err)
		}
	}
}

var (
	orgReasons = []string{"the legal form llc", "an organization is stored under the name",
		"the record's organization is Acme LLC"}
	personReasons = []string{"the middle initial q", "the email plee@example.com spells it"}
)

type fakeNameApplier struct{}

func (fakeNameApplier) ApplyNameKind(_ context.Context, _ review.NameKindProposal, kind string,
	_ int) (review.NameKindOutcome, error) {
	return review.NameKindOutcome{EntityID: kind + ":1"}, nil
}

func (fakeNameApplier) RetractNameKind(context.Context, review.NameKindProposal, review.NameKindOutcome) error {
	return nil
}

// Only people's -as decisions are labels: an organization positive, a
// person negative.
func TestNameKindExamples(t *testing.T) {
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	namesDecided(t, j, 4)

	auto := review.NameKindProposal{ID: review.NameKindProposalID("rec", "person", "Auto Co"), RecordID: "rec",
		Label: "person", Name: "Auto Co"}
	rejected := review.NameKindProposal{ID: review.NameKindProposalID("rec", "person", "Nobody"), RecordID: "rec",
		Label: "person", Name: "Nobody"}
	if _, err := j.SubmitNameKinds([]review.NameKindProposal{auto, rejected}); err != nil {
		t.Fatal(err)
	}
	if _, err := review.ApplyNameKind(context.Background(), fakeNameApplier{}, j, auto.ID, review.NameKindOrganization,
		"amass-ai (model test)", 95, ""); err != nil {
		t.Fatal(err)
	}
	if err := review.RejectNameKind(j, rejected.ID, "jeff"); err != nil {
		t.Fatal(err)
	}

	rows, _, err := nameKindExamples(j)
	if err != nil {
		t.Fatal(err)
	}
	var pos, neg int
	for _, r := range rows {
		if r.Label == labelPositive {
			pos++
		} else {
			neg++
		}
	}
	if pos != 2 || neg != 2 {
		t.Errorf("%d organizations, %d people from %+v", pos, neg, rows)
	}
}

// A trained name-kind classifier answers both ways first; its answers are
// advice unless it may apply, and the main model decides what it is unsure
// of, or what it may only advise on.
func TestNameKindDecider(t *testing.T) {
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	namesDecided(t, j, 60)
	m, _, err := NameKindKind.TrainFromJournal(j, "names-test")
	if err != nil {
		t.Fatal(err)
	}
	if m.ReviewThreshold < NameKindKind.MinThreshold || m.SkipThreshold < NameKindKind.MinThreshold {
		t.Fatalf("thresholds %.2f/%.2f", m.ReviewThreshold, m.SkipThreshold)
	}

	org := &et.NameKindQuestion{Name: "Widgets LLC", Label: "person", RecordType: "ContactRecord",
		Reasons: orgReasons, Evidence: []string{"the name rules found: the legal form llc"}}
	person := &et.NameKindQuestion{Name: "Ann Q Smith", Label: "person", RecordType: "ContactRecord",
		Reasons: personReasons, Evidence: []string{"x"}}
	ctx := context.Background()

	alone := &NameKindDecider{Classifier: m}
	a, err := alone.Decide(ctx, org)
	if err != nil || a.Kind != et.NameKindOrganization || !a.AdviceOnly || a.DecidedBy != "classifier names-test" {
		t.Errorf("classifier alone, organization: %+v, %v", a, err)
	}
	if a, err = alone.Decide(ctx, person); err != nil || a.Kind != et.NameKindPerson {
		t.Errorf("classifier alone, person: %+v, %v", a, err)
	}

	model := &replyModel{reply: `{"kind":"person","confidence":0.95,"reason":"r","cites":[1]}`}
	advising := &NameKindDecider{Classifier: m, Model: &NameKindModel{Model: model, ModelID: "test"}}
	if a, err = advising.Decide(ctx, org); err != nil || model.calls != 1 || a.DecidedBy != "" {
		t.Errorf("advising classifier with a model: %+v, %v, %d calls", a, err, model.calls)
	}

	applying := &NameKindDecider{Classifier: m, Applies: true, Model: &NameKindModel{Model: model, ModelID: "test"}}
	if a, err = applying.Decide(ctx, org); err != nil || a.AdviceOnly || a.Kind != et.NameKindOrganization ||
		model.calls != 1 {
		t.Errorf("applying classifier: %+v, %v, %d calls", a, err, model.calls)
	}
}

// The main model's confident answers teach the classifier: decisions it
// applied at 0.90 or above that stand, and confident advice citing evidence
// on names still waiting; never the classifier's own, a weak answer, or
// advice without citations.
func TestNameKindModelExamples(t *testing.T) {
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	ctx := context.Background()
	submit := func(name string) review.NameKindProposal {
		t.Helper()
		p := review.NameKindProposal{ID: review.NameKindProposalID("rec", "person", name), RecordID: "rec",
			RecordType: "ContactRecord", Label: "person", Name: name, Reasons: orgReasons}
		if _, err := j.SubmitNameKinds([]review.NameKindProposal{p}); err != nil {
			t.Fatal(err)
		}
		return p
	}
	apply := func(name, reviewer string, conf int) {
		t.Helper()
		p := submit(name)
		if _, err := review.ApplyNameKind(ctx, fakeNameApplier{}, j, p.ID, review.NameKindOrganization, reviewer,
			conf, ""); err != nil {
			t.Fatal(err)
		}
	}
	advise := func(name, model string, conf int, cites []string) {
		t.Helper()
		p := submit(name)
		if err := j.RecordNameKindAdvice(review.NameKindAdvice{ProposalID: p.ID, Model: model,
			Kind: review.NameKindPerson, Confidence: conf, Cites: cites}); err != nil {
			t.Fatal(err)
		}
	}

	apply("A LLC", "amass-ai (model anthropic/test)", 95)
	apply("B LLC", "amass-ai (model anthropic/test)", 80)
	apply("C LLC", "amass-ai (classifier names-1)", 99)
	apply("D LLC", "jeff", 100)
	advise("E Smith", "model anthropic/test", 92, []string{"the email spells it"})
	advise("F Smith", "model anthropic/test", 92, nil)
	advise("G Smith", "classifier names-1", 99, []string{"x"})

	rows, err := nameKindModelExamples(j)
	if err != nil {
		t.Fatal(err)
	}
	var pos, neg int
	for _, r := range rows {
		if r.Label == labelPositive {
			pos++
		} else {
			neg++
		}
	}
	if pos != 1 || neg != 1 {
		t.Errorf("%d organizations and %d people from the model: %+v", pos, neg, rows)
	}
	if p, n, m, err := NameKindKind.LabelCounts(j); err != nil || p != 1 || n != 0 || m != 2 {
		t.Errorf("label counts %d/%d/%d, %v", p, n, m, err)
	}
}

// A model's answers add to people's decisions in training, and the
// classifier is still judged on people's alone.
func TestNameKindTrainsWithModelAnswers(t *testing.T) {
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	namesDecided(t, j, 60)
	for i := 0; i < 20; i++ {
		w := string(rune('a'+i/26)) + string(rune('a'+i%26))
		name, kind := "Model"+w+" Inc", review.NameKindOrganization
		if i%2 == 1 {
			name, kind = "Kim Q Model"+w, review.NameKindPerson
		}
		reasons := orgReasons
		if kind == review.NameKindPerson {
			reasons = personReasons
		}
		p := review.NameKindProposal{ID: review.NameKindProposalID("rec", "person", name), RecordID: "rec",
			RecordType: "ContactRecord", Label: "person", Name: name, Reasons: reasons}
		if _, err := j.SubmitNameKinds([]review.NameKindProposal{p}); err != nil {
			t.Fatal(err)
		}
		if _, err := review.ApplyNameKind(context.Background(), fakeNameApplier{}, j, p.ID, kind,
			"amass-ai (model anthropic/test)", 95, ""); err != nil {
			t.Fatal(err)
		}
	}

	m, metrics, err := NameKindKind.TrainFromJournal(j, "names-mixed")
	if err != nil {
		t.Fatal(err)
	}
	if metrics.TrainingExamples+metrics.HoldoutExamples != 80 || m.ReviewThreshold < NameKindKind.MinThreshold {
		t.Errorf("trained on %d rows, threshold %.2f", metrics.TrainingExamples+metrics.HoldoutExamples,
			m.ReviewThreshold)
	}
}

// One name in ten the classifier is sure of is still asked of the main
// model: agreement keeps the classifier's answer, disagreement leaves the
// name to a person with both answers.
func TestNameKindAudit(t *testing.T) {
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	namesDecided(t, j, 60)
	m, _, err := NameKindKind.TrainFromJournal(j, "names-audit")
	if err != nil {
		t.Fatal(err)
	}

	var audited, skipped string
	for i := 0; i < 1000 && (audited == "" || skipped == ""); i++ {
		name := fmt.Sprintf("Widgets%d LLC", i)
		if nameKindAudited(name) {
			audited = name
		} else {
			skipped = name
		}
	}
	q := func(name string) *et.NameKindQuestion {
		return &et.NameKindQuestion{Name: name, Label: "person", RecordType: "ContactRecord", Reasons: orgReasons,
			Evidence: []string{"the name rules found: the legal form llc"}}
	}
	ctx := context.Background()

	disagree := &replyModel{reply: `{"kind":"person","confidence":0.95,"reason":"an email spells it","cites":[1]}`}
	d := &NameKindDecider{Classifier: m, Applies: true, Model: &NameKindModel{Model: disagree, ModelID: "test"}}
	if a, err := d.Decide(ctx, q(skipped)); err != nil || a.Kind != et.NameKindOrganization || disagree.calls != 0 {
		t.Errorf("not audited: %+v, %v, %d calls", a, err, disagree.calls)
	}
	a, err := d.Decide(ctx, q(audited))
	if err != nil || disagree.calls != 1 || !a.AdviceOnly || a.Kind != et.NameKindPerson ||
		!strings.Contains(a.Reason, "the classifier answered organization") {
		t.Errorf("audited, disagreeing: %+v, %v", a, err)
	}

	agree := &replyModel{reply: `{"kind":"organization","confidence":0.95,"reason":"a legal form","cites":[1]}`}
	d.Model = &NameKindModel{Model: agree, ModelID: "test"}
	if a, err := d.Decide(ctx, q(audited)); err != nil || agree.calls != 1 || a.AdviceOnly ||
		!strings.HasPrefix(a.DecidedBy, "classifier") {
		t.Errorf("audited, agreeing: %+v, %v", a, err)
	}
}

// A person stored under an organization's name gets the trained name-kind
// classifier's answer as advice when it is proposed; without a classifier,
// or when it is unsure, none.
func TestOrgNamedAdvice(t *testing.T) {
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	candidates := []lens.OrgNamedPerson{
		{ID: lens.OrgNamedID("p-1"), PersonID: "p-1", Person: "Widgets LLC", ContactIDs: []string{"cr"},
			Reasons: orgReasons},
		{ID: lens.OrgNamedID("p-2"), PersonID: "p-2", Person: "Ann Q Smith", ContactIDs: []string{"cr"},
			Reasons: personReasons},
		{ID: lens.OrgNamedID("p-3"), PersonID: "p-3", Person: "Zz"},
	}
	if err := OrgNamedAdvice(j, candidates); err != nil || candidates[0].Advice != nil {
		t.Fatalf("advice with no classifier: %+v, %v", candidates[0].Advice, err)
	}

	namesDecided(t, j, 60)
	m, _, err := NameKindKind.TrainFromJournal(j, "names-onp")
	if err != nil {
		t.Fatal(err)
	}
	if err := NameKindKind.Save(m, NameKindKind.Path(j.Path)); err != nil {
		t.Fatal(err)
	}
	if err := OrgNamedAdvice(j, candidates); err != nil {
		t.Fatal(err)
	}
	if a := candidates[0].Advice; a == nil || a.Kind != et.NameKindOrganization || a.Model != "classifier names-onp" ||
		a.Confidence < 90 {
		t.Errorf("organization advice = %+v", a)
	}
	if a := candidates[1].Advice; a == nil || a.Kind != et.NameKindPerson {
		t.Errorf("person advice = %+v", a)
	}
	if a := candidates[2].Advice; a != nil {
		t.Errorf("advice with no evidence = %+v", a)
	}
}
