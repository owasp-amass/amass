// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/ai/classify"
	"github.com/owasp-amass/amass/v5/internal/review"
	dbt "github.com/owasp-amass/asset-db/types"
)

// An adjudicator is a small local classifier that answers one question a
// model would otherwise be asked (does this organization own this asset,
// does this domain belong in scope), learned from people's review decisions.
// Each question is an AdjudicatorKind: what is specific to it is its
// features and which journal decisions are its labels; training, loading,
// scoring and the commands are shared. Until a kind is trained, its rules,
// the main model or a person decide, so an adjudicator is never required.
type AdjudicatorKind struct {
	// Name is the kind's name in `amass ai train -kind` and `status`.
	Name string
	// Question says what the kind decides, for status output.
	Question string
	// Task and FeatureVersion are checked when a model is loaded, so a
	// model trained for another question or other features is refused.
	Task           string
	FeatureVersion string
	// File is the model's file name beside the review journal, when the
	// journal is a file (otherwise the model is kept in ModelTopic).
	File string
	// Examples reads the journal's labels: people's decisions only, never
	// pending, automatic or re-check ones. It also returns every feature
	// the examples use.
	Examples func(j *review.Journal) ([]classify.LabeledExample, []string, error)
	// ModelExamples, when set, reads a main model's confident answers as
	// extra rows that teach the classifier but never judge it; people's
	// decisions always win where both exist.
	ModelExamples func(j *review.Journal) ([]classify.LabeledExample, error)
	// MinExamples is the fewest labels (people's and the model's) a model is
	// trained from.
	MinExamples int
	// MinPrecision is the held-out precision a model needs; MinThreshold the
	// lowest probability that may ever decide.
	MinPrecision float64
	MinThreshold float64
	// TwoSided kinds decide both classes (a name is an organization's or a
	// person's): the negative class has its own threshold (the model's
	// SkipThreshold, on the negative class's probability). Other kinds
	// decide only the positive class.
	TwoSided bool
	// Positive and Negative name a two-sided kind's classes, for output.
	Positive, Negative string
	// UsedBy says what decides with a trained model, for status output.
	UsedBy string
}

// The two labels classify trains on: a kind's positive class (the relation
// holds, the domain belongs) and its negative class.
const (
	labelPositive = "potential_relation"
	labelNegative = "unrelated"
)

// modelLabelConfidence is the confidence a main model's decision needs to
// teach a classifier (ModelExamples).
const modelLabelConfidence = 90

// isMainModel reports whether by, a decider's name (NameKindModel.Name,
// AdmissionModel.Name), names the main model rather than a classifier.
func isMainModel(by string) bool {
	return strings.HasPrefix(by, "model ")
}

// decidedByMainModel reports whether a journal reviewer, "amass-ai (<by>)",
// is the main model's.
func decidedByMainModel(reviewer string) bool {
	return isMainModel(strings.TrimPrefix(reviewer, review.InferenceSource+" ("))
}

// AdjudicatorKinds are the questions an adjudicator can be trained for.
func AdjudicatorKinds() []*AdjudicatorKind {
	return []*AdjudicatorKind{OwnershipKind, HorizontalKind, NameKindKind}
}

// LookupAdjudicatorKind returns the kind named name.
func LookupAdjudicatorKind(name string) (*AdjudicatorKind, bool) {
	for _, k := range AdjudicatorKinds() {
		if k.Name == name {
			return k, true
		}
	}
	return nil, false
}

// ModelTopic is the Asset Database journal's topic of trained models: each
// record, of a kind's name, is one of its models, and the newest is used,
// so every engine and tool on the database decides with the same model.
const ModelTopic = "models"

// Path is where the kind's model file for a journal file lives.
func (k *AdjudicatorKind) Path(journal string) string {
	return filepath.Join(filepath.Dir(journal), k.File)
}

// Load reads the kind's model file at path. A missing file is no model.
func (k *AdjudicatorKind) Load(path string) (*classify.LinearModel, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()
	return k.read(f, path)
}

// read reads one of the kind's models from r; where names it in errors.
func (k *AdjudicatorKind) read(r io.Reader, where string) (*classify.LinearModel, error) {
	m, err := classify.Load(r)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", where, err)
	}
	if m.Task != k.Task || m.FeatureVersion != k.FeatureVersion {
		return nil, fmt.Errorf("%s is a %s/%s model, not %s/%s", where, m.Task, m.FeatureVersion, k.Task,
			k.FeatureVersion)
	}
	return m, nil
}

// LoadFor returns the kind's newest model for the journal: the database's
// (ModelTopic) when the journal is kept in the Asset Database and has one,
// otherwise the file beside the journal's path. No journal, or no model, is
// nil and no error.
func (k *AdjudicatorKind) LoadFor(j *review.Journal) (*classify.LinearModel, error) {
	m, _, err := k.Find(j)
	return m, err
}

// Find is LoadFor, also saying where the model was found, or, without one,
// where Keep would store it.
func (k *AdjudicatorKind) Find(j *review.Journal) (*classify.LinearModel, string, error) {
	if j == nil {
		return nil, "", nil
	}
	if t := j.Sibling(ModelTopic); t != nil {
		recs, err := t.ReadWhere(dbt.JournalFilter{Kinds: []string{k.Name}}, 0)
		if err != nil {
			return nil, "", err
		}
		if len(recs) > 0 {
			where := k.Where(j)
			m, err := k.read(bytes.NewReader(recs[len(recs)-1].Data), where)
			return m, where, err
		}
	}
	if j.Path == "" {
		return nil, k.Where(j), nil
	}
	path := k.Path(j.Path)
	m, err := k.Load(path)
	if m == nil {
		return m, k.Where(j), err
	}
	return m, path, err
}

// Where says where Keep stores the kind's model for the journal, for
// messages.
func (k *AdjudicatorKind) Where(j *review.Journal) string {
	if j.Shared() {
		return "the Asset Database (" + ModelTopic + ")"
	}
	return k.Path(j.Path)
}

// Keep stores a trained model where LoadFor finds it: in the database when
// the journal is kept there, so every engine on it uses the model, otherwise
// as the file beside the journal's path.
func (k *AdjudicatorKind) Keep(j *review.Journal, m *classify.LinearModel) error {
	if t := j.Sibling(ModelTopic); t != nil {
		raw, err := json.Marshal(m)
		if err != nil {
			return err
		}
		_, err = t.Append(k.Name, m.ModelID, json.RawMessage(raw))
		return err
	}
	if j == nil || j.Path == "" {
		return errors.New("-journal required")
	}
	return k.Save(m, k.Path(j.Path))
}

// Train trains the kind's model on people's labeled rows using features
// (TrainWith, with no model rows).
func (k *AdjudicatorKind) Train(rows []classify.LabeledExample, features []string,
	modelID string) (*classify.LinearModel, classify.TrainingMetrics, error) {
	return k.TrainWith(rows, nil, features, modelID)
}

// TrainWith trains the kind's model on people's rows and, as extra teaching
// only, a main model's confident answers (model). People's decisions alone
// judge it: the held-out part of them (never trained on) must meet
// MinPrecision, for each class that decides, and the thresholds to decide
// are set just above the highest probability any of their examples of the
// other class received, never below MinThreshold, so the model decides
// nothing a reviewer labeled otherwise.
func (k *AdjudicatorKind) TrainWith(people, model []classify.LabeledExample, features []string,
	modelID string) (*classify.LinearModel, classify.TrainingMetrics, error) {
	spec := classify.LinearSpec{Task: k.Task, FeatureVersion: k.FeatureVersion, Features: features}
	m, metrics, err := classify.TrainLinear(append(append([]classify.LabeledExample{}, people...), model...),
		modelID, spec)
	if err != nil {
		return nil, metrics, err
	}

	// classify holds out the same rows (by group), so these were not trained on
	var check []classify.LabeledExample
	for _, r := range people {
		if classify.HeldOut(r.GroupID) {
			check = append(check, r)
		}
	}
	pos, neg, err := heldOutPrecision(m, check)
	if err != nil {
		return nil, metrics, err
	}
	if pos < k.MinPrecision || (k.TwoSided && neg < k.MinPrecision) {
		return nil, metrics, fmt.Errorf("on the decisions held out to check it, precision %.2f (%.2f the other way) "+
			"is below %.2f; review more and train again", pos, neg, k.MinPrecision)
	}
	metrics.HoldoutPotentialPrecision = pos

	positive, negative := k.MinThreshold, k.MinThreshold
	for _, r := range people {
		prob, err := m.ClassifyUnrestricted(r.Features)
		if err != nil {
			return nil, metrics, err
		}
		if r.Label == labelNegative {
			positive = math.Max(positive, prob+0.01)
		} else {
			negative = math.Max(negative, 1-prob+0.01)
		}
	}
	if positive > 0.99 || (k.TwoSided && negative > 0.99) {
		return nil, metrics, errors.New("rejected proposals score too close to approved ones to decide any automatically")
	}

	m.ReviewThreshold = positive
	if k.TwoSided {
		m.SkipThreshold = negative
	}
	return m, metrics, m.Validate()
}

// heldOutPrecision is the precision on people's held-out decisions of each
// class's prediction (at 0.5). Too few of either class to judge is an error.
func heldOutPrecision(m *classify.LinearModel, check []classify.LabeledExample) (positive, negative float64,
	err error) {
	var npos, nneg, tp, fp, tn, fn int
	for _, r := range check {
		prob, err := m.ClassifyUnrestricted(r.Features)
		if err != nil {
			return 0, 0, err
		}
		isPos := r.Label != labelNegative
		if isPos {
			npos++
		} else {
			nneg++
		}
		switch {
		case prob >= 0.5 && isPos:
			tp++
		case prob >= 0.5:
			fp++
		case !isPos:
			tn++
		default:
			fn++
		}
	}
	if npos < minCheckEach || nneg < minCheckEach {
		return 0, 0, fmt.Errorf("%d and %d of your decisions of each kind are held out to check the model; %d of "+
			"each are needed, so review more and train again", npos, nneg, minCheckEach)
	}
	share := func(a, b int) float64 {
		if b == 0 {
			return 0
		}
		return float64(a) / float64(b)
	}
	return share(tp, tp+fp), share(tn, tn+fn), nil
}

// minCheckEach is the fewest of people's held-out decisions of each class a
// model is judged on.
const minCheckEach = 2

// TrainFromJournal reads the kind's labels from the journal (people's and,
// for a kind that learns from the main model, its confident answers) and
// trains a model on them, refusing fewer than MinExamples in all.
func (k *AdjudicatorKind) TrainFromJournal(j *review.Journal, modelID string) (*classify.LinearModel,
	classify.TrainingMetrics, error) {
	people, features, err := k.Examples(j)
	if err != nil {
		return nil, classify.TrainingMetrics{}, err
	}
	var model []classify.LabeledExample
	if k.ModelExamples != nil {
		if model, err = k.ModelExamples(j); err != nil {
			return nil, classify.TrainingMetrics{}, err
		}
		features = featureNames(append(append([]classify.LabeledExample{}, people...), model...))
	}
	if n := len(people) + len(model); n < k.MinExamples {
		return nil, classify.TrainingMetrics{}, fmt.Errorf("%d labeled example(s); %d are needed", n, k.MinExamples)
	}
	return k.TrainWith(people, model, features, modelID)
}

// Save writes a trained model to path atomically.
func (k *AdjudicatorKind) Save(m *classify.LinearModel, path string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Thresholds describes the probabilities m decides at, for output.
func (k *AdjudicatorKind) Thresholds(m *classify.LinearModel) string {
	if k.TwoSided {
		return fmt.Sprintf("%s at a probability of %.2f, %s at %.2f", k.Positive, m.ReviewThreshold, k.Negative,
			m.SkipThreshold)
	}
	return fmt.Sprintf("at a probability of %.2f", m.ReviewThreshold)
}

// LabelCounts counts the kind's labels in the journal: people's, positive
// and negative, and the main model's confident answers it also learns from.
func (k *AdjudicatorKind) LabelCounts(j *review.Journal) (positive, negative, model int, err error) {
	rows, _, err := k.Examples(j)
	if err != nil {
		return 0, 0, 0, err
	}
	for _, r := range rows {
		if r.Label == labelNegative {
			negative++
		} else {
			positive++
		}
	}
	if k.ModelExamples != nil {
		extra, err := k.ModelExamples(j)
		if err != nil {
			return 0, 0, 0, err
		}
		model = len(extra)
	}
	return positive, negative, model, nil
}

// adjudicatorProbability scores features with m, ignoring the features m
// never saw.
func adjudicatorProbability(m *classify.LinearModel, features map[string]float64) (float64, error) {
	known := map[string]bool{}
	for _, name := range m.Features() {
		known[name] = true
	}

	f := map[string]float64{}
	for k, v := range features {
		if known[k] {
			f[k] = v
		}
	}
	return m.ClassifyUnrestricted(f)
}

// featureNames returns the sorted features the rows use.
func featureNames(rows []classify.LabeledExample) []string {
	names := map[string]bool{}
	for _, r := range rows {
		for k := range r.Features {
			names[k] = true
		}
	}

	out := make([]string, 0, len(names))
	for k := range names {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
