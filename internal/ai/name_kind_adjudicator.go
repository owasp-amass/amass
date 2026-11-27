// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"strings"
	"unicode"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/ai/classify"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// The name-kind classifier learns, from people's decisions on name proposals
// (amass review approve -as person|organization), whether a name found in a
// person's field names an organization (the positive class) or a person.
const (
	NameKindTask           = "name_kind"
	NameKindFeatureVersion = "name-kind-v1"
)

// NameKindKind is the name question: does a name a record gives in a
// person's field name a person or an organization.
var NameKindKind = &AdjudicatorKind{
	Name:           "name_kind",
	Question:       "whether a name in a person's field is a person's or an organization's",
	Task:           NameKindTask,
	FeatureVersion: NameKindFeatureVersion,
	File:           "name-kind-model.json",
	Examples:       nameKindExamples,
	ModelExamples:  nameKindModelExamples,
	MinExamples:    20,
	MinPrecision:   0.9,
	// the bar a name decision is applied at
	MinThreshold: 0.9,
	TwoSided:     true,
	Positive:     "organization",
	Negative:     "person",
	UsedBy:       "the engine's name decisions, before the main model",
}

// nameKindReasonFeatures map what the name rules weighed (the start of each
// reason semantics.NameKindOf gives) to features.
var nameKindReasonFeatures = []struct{ prefix, feature string }{
	{"the legal form ", "rule:legal_form"},
	{"the institution word ", "rule:institution_word"},
	{"the governance prefix ", "rule:governance_prefix"},
	{"the record's organization is ", "rule:record_organization"},
	{"an organization is stored under the name", "rule:stored_organization"},
	{"the title ", "rule:person_title"},
	{"the middle initial ", "rule:middle_initial"},
	{"the email ", "rule:email_spells_it"},
	{"it does not read as a person's name", "rule:not_a_person_name"},
}

// NameKindFeatures describes a name for the name-kind classifier, from what
// its proposal records: the reasons the rules weighed, the name's shape, the
// field that gave it and the record type. Every value is in 0..1.
func NameKindFeatures(name, label, recordType string, reasons []string) map[string]float64 {
	f := map[string]float64{}
	for _, r := range reasons {
		for _, m := range nameKindReasonFeatures {
			if strings.HasPrefix(r, m.prefix) {
				f[m.feature] = 1
			}
		}
		if strings.HasSuffix(r, " is also a family name") {
			f["rule:family_name_form"] = 1
		}
	}

	name = strings.TrimSpace(name)
	words := strings.Fields(name)
	f["words"] = math.Min(float64(len(words)), 6) / 6
	if strings.Contains(name, ",") {
		f["shape:comma"] = 1
	}
	if strings.IndexFunc(name, unicode.IsDigit) >= 0 {
		f["shape:digits"] = 1
	}
	if strings.ToUpper(name) == name && strings.ToLower(name) != name {
		f["shape:all_caps"] = 1
	}
	if _, ok := semantics.ParsePersonName(name); ok {
		f["shape:parses_as_person"] = 1
	}
	if label != "" {
		f["field:"+strings.ToLower(label)] = 1
	}
	if recordType != "" {
		f["record:"+recordType] = 1
	}
	return f
}

// nameKindExamples are people's decisions on the question in all three of
// its forms. On a name proposal, approving it as an organization is
// positive and as a person negative; a rejection names neither and a
// retraction does not say which it was, so neither is a label. Approving a
// conversion of a person stored under an organization's name (onp-) is
// positive and rejecting it negative; the reverse for an organization
// stored under a person's name (pno-). No amass-ai decision is a label.
func nameKindExamples(j *review.Journal) ([]classify.LabeledExample, []string, error) {
	var rows []classify.LabeledExample
	byPerson := func(reviewer string) bool {
		return reviewer != "" && !strings.HasPrefix(reviewer, review.InferenceSource)
	}
	add := func(id string, org bool, f map[string]float64) {
		label := labelNegative
		if org {
			label = labelPositive
		}
		rows = append(rows, classify.LabeledExample{GroupID: id, Label: label, Features: f})
	}

	names, err := j.NameKindEntries()
	if err != nil {
		return nil, nil, err
	}
	// one decision decides a name's whole group (review.NameKindGroup), so a
	// group is one example, not one per record, under its first proposal's ID
	// (entries come sorted by group, then ID)
	seen := map[string]bool{}
	for _, e := range names {
		p := e.Proposal
		if o := e.Outcome; e.Status == review.ProposalApplied && o != nil && byPerson(o.Reviewer) && !seen[p.Group()] {
			seen[p.Group()] = true
			add(p.ID, o.Kind == review.NameKindOrganization,
				NameKindFeatures(p.Name, p.Label, p.RecordType, p.Reasons))
		}
	}

	people, err := j.OrgNamedEntries()
	if err != nil {
		return nil, nil, err
	}
	for _, e := range people {
		o := e.Outcome
		if o == nil || !byPerson(o.Reviewer) || (e.Status != review.ProposalApplied && e.Status != review.ProposalRejected) {
			continue
		}
		add(e.Proposal.ID, e.Status == review.ProposalApplied, OrgNamedFeatures(e.Proposal))
	}

	orgs, err := j.PersonNamedEntries()
	if err != nil {
		return nil, nil, err
	}
	for _, e := range orgs {
		o := e.Outcome
		if o == nil || !byPerson(o.Reviewer) || (e.Status != review.ProposalApplied && e.Status != review.ProposalRejected) {
			continue
		}
		// these proposals keep no reasons, so the rules weigh the name again
		p := e.Proposal
		var clues semantics.NameClues
		if pn, ok := semantics.ParsePersonName(p.Organization); ok {
			clues.First, clues.Middle, clues.Last = pn.First, pn.Middle, pn.Last
		}
		_, reasons := semantics.NameKindOf(p.Organization, clues)
		add(p.ID, e.Status == review.ProposalRejected,
			NameKindFeatures(p.Organization, "organization", "ContactRecord", reasons))
	}
	return rows, featureNames(rows), nil
}

// Bounds on learning from the main model and checking the classifier.
const (
	// nameKindModelLabelConfidence is the confidence a main model's answer
	// needs to teach the classifier.
	nameKindModelLabelConfidence = modelLabelConfidence
	// nameKindAuditEvery: one name in this many that the classifier is sure
	// of is still asked of the main model, to check it.
	nameKindAuditEvery = 10
)

// nameKindModelExamples are a main model's confident answers on names no
// person decided: decisions it applied at nameKindModelLabelConfidence or
// above that nobody retracted, and its advice at that confidence, citing
// evidence, on names still waiting. The classifier's own answers are never
// among them, and a person's decision replaces the model's.
func nameKindModelExamples(j *review.Journal) ([]classify.LabeledExample, error) {
	entries, err := j.NameKindEntries()
	if err != nil {
		return nil, err
	}

	var rows []classify.LabeledExample
	seen := map[string]bool{}
	for _, e := range entries {
		if seen[e.Proposal.Group()] {
			// an answer covers its name's whole group: one example
			continue
		}
		var kind string
		switch o, a := e.Outcome, e.Advice; {
		case e.Status == review.ProposalApplied && o != nil && decidedByMainModel(o.Reviewer) &&
			o.Confidence >= nameKindModelLabelConfidence:
			kind = o.Kind
		case e.Status == review.ProposalPending && a != nil && isMainModel(a.Model) &&
			a.Confidence >= nameKindModelLabelConfidence && len(a.Cites) > 0:
			kind = a.Kind
		default:
			continue
		}

		label := labelNegative
		switch kind {
		case review.NameKindOrganization:
			label = labelPositive
		case review.NameKindPerson:
		default:
			continue
		}
		p := e.Proposal
		seen[p.Group()] = true
		rows = append(rows, classify.LabeledExample{GroupID: p.ID, Label: label,
			Features: NameKindFeatures(p.Name, p.Label, p.RecordType, p.Reasons)})
	}
	return rows, nil
}

// NameKindDecider answers what an uncertain name names: a trained name-kind
// classifier first, and the main model when the classifier is unsure, or
// when the classifier may only advise and a model is there to decide. The
// classifier's answers are advice unless Applies (options.ai
// classifier_applies) is set.
type NameKindDecider struct {
	Classifier *classify.LinearModel
	Applies    bool
	Model      *NameKindModel
}

var _ et.NameKindDecider = (*NameKindDecider)(nil)

// Name implements et.NameKindDecider.
func (d *NameKindDecider) Name() string {
	if d.Model != nil {
		return d.Model.Name()
	}
	if d.Classifier != nil {
		return "classifier " + d.Classifier.ModelID
	}
	return "nothing"
}

// Decide implements et.NameKindDecider.
func (d *NameKindDecider) Decide(ctx context.Context, q *et.NameKindQuestion) (et.NameKindAnswer, error) {
	if q == nil {
		return et.NameKindAnswer{}, errors.New("no name to decide")
	}
	if d.Classifier != nil && (d.Applies || d.Model == nil) {
		if a, ok := d.classify(q); ok {
			if d.Model == nil || !nameKindAudited(q.Name) {
				return a, nil
			}
			return d.audit(ctx, q, a), nil
		}
	}
	if d.Model != nil {
		return d.Model.Decide(ctx, q)
	}
	return et.NameKindAnswer{}, errors.New("the classifier is not sure and there is no main model")
}

// nameKindAudited reports whether a name the classifier is sure of is one
// of those still asked of the main model, chosen by its hash so a run asked
// again checks the same names.
func nameKindAudited(name string) bool {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(strings.TrimSpace(name))))
	return h.Sum32()%nameKindAuditEvery == 0
}

// audit asks the main model about a name the classifier is sure of. When
// they agree, or the model cannot answer, the classifier's answer stands;
// when they disagree, nothing is applied: the model's answer is kept as
// advice, naming the classifier's, for a person to decide.
func (d *NameKindDecider) audit(ctx context.Context, q *et.NameKindQuestion, a et.NameKindAnswer) et.NameKindAnswer {
	m, err := d.Model.Decide(ctx, q)
	if err != nil || m.Kind == a.Kind {
		return a
	}

	m.DecidedBy, m.AdviceOnly = d.Model.Name(), true
	m.Reason = fmt.Sprintf("the classifier answered %s at %d and the model %s: %s", a.Kind, a.Confidence, m.Kind,
		m.Reason)
	return m
}

// classify answers with the classifier when its probability clears the
// threshold of either class.
func (d *NameKindDecider) classify(q *et.NameKindQuestion) (et.NameKindAnswer, bool) {
	kind, confidence, ok := NameKindClassified(d.Classifier,
		NameKindFeatures(q.Name, q.Label, q.RecordType, q.Reasons))
	if !ok {
		return et.NameKindAnswer{}, false
	}
	return et.NameKindAnswer{Kind: kind, Confidence: confidence, DecidedBy: "classifier " + d.Classifier.ModelID,
		AdviceOnly: !d.Applies, Reason: "learned from the names people decided, with the same evidence"}, true
}

// NameKindClassified is the name-kind classifier m's answer for a name's
// features: organization or person, with its confidence, when the
// probability clears that class's threshold; ok is false when m is unsure.
func NameKindClassified(m *classify.LinearModel, features map[string]float64) (kind string, confidence int,
	ok bool) {
	if m == nil {
		return "", 0, false
	}
	p, err := adjudicatorProbability(m, features)
	if err != nil {
		return "", 0, false
	}

	switch {
	case p >= m.ReviewThreshold:
		return et.NameKindOrganization, int(p * 100), true
	case 1-p >= m.SkipThreshold:
		return et.NameKindPerson, int((1 - p) * 100), true
	}
	return "", 0, false
}

// OrgNamedFeatures describes a person stored under an organization's name
// (an onp- proposal) for the name-kind classifier: the stored name as a
// contact's person field, with what the name rules weighed.
func OrgNamedFeatures(p lens.OrgNamedPerson) map[string]float64 {
	record := ""
	if len(p.ContactIDs) > 0 {
		record = "ContactRecord"
	}
	return NameKindFeatures(p.Person, "person", record, p.Reasons)
}

// OrgNamedAdvice gives each candidate the trained name-kind classifier's
// answer, the journal's newest (NameKindKind.LoadFor), when there is one and
// it is sure, so the answer is recorded with the proposal as advice for the
// reviewer.
func OrgNamedAdvice(j *review.Journal, candidates []lens.OrgNamedPerson) error {
	if j == nil {
		return nil
	}
	m, err := NameKindKind.LoadFor(j)
	if err != nil || m == nil {
		return err
	}
	for i := range candidates {
		if kind, confidence, ok := NameKindClassified(m, OrgNamedFeatures(candidates[i])); ok {
			candidates[i].Advice = &lens.NameKindAdvice{Model: "classifier " + m.ModelID, Kind: kind,
				Confidence: confidence}
		}
	}
	return nil
}
