// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// adjudicatorKinds returns the kind named, or every kind when name is empty.
func adjudicatorKinds(name string) ([]*ai.AdjudicatorKind, error) {
	if name == "" {
		return ai.AdjudicatorKinds(), nil
	}
	if k, ok := ai.LookupAdjudicatorKind(name); ok {
		return []*ai.AdjudicatorKind{k}, nil
	}

	var names []string
	for _, k := range ai.AdjudicatorKinds() {
		names = append(names, k.Name)
	}
	return nil, fmt.Errorf("no adjudicator kind %q; the kinds are %v", name, names)
}

// trainAdjudicators trains the named kind, or every kind with enough labels,
// from the journal's review decisions, and writes each model where the
// engine and amass ai load it. output overrides the file of a single kind.
func trainAdjudicators(j *review.Journal, kind, output string, out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}
	kinds, err := adjudicatorKinds(kind)
	if err != nil {
		return err
	}
	if output != "" && len(kinds) != 1 {
		return errors.New("-model-output needs -kind")
	}

	trained := 0
	for _, k := range kinds {
		id := k.Name + "-" + time.Now().UTC().Format("20060102-150405")
		m, metrics, err := k.TrainFromJournal(j, id)
		if err != nil {
			if len(kinds) == 1 {
				return fmt.Errorf("train %s: %w", k.Name, err)
			}
			_, _ = fmt.Fprintf(out, "%s: not trained: %v.\n", k.Name, err)
			continue
		}

		where := output
		if where != "" {
			err = k.Save(m, where)
		} else {
			where, err = k.Where(j), k.Keep(j, m)
		}
		if err != nil {
			return err
		}
		trained++
		_, _ = fmt.Fprintf(out, "%s: trained %s from %d reviewed decisions (%d held out): accuracy %.2f, "+
			"precision %.2f, recall %.2f. It decides %s. Saved to %s; %s use it from the next run.\n", k.Name,
			m.ModelID, metrics.TrainingExamples+metrics.HoldoutExamples, metrics.HoldoutExamples,
			metrics.HoldoutAccuracy, metrics.HoldoutPotentialPrecision, metrics.HoldoutPotentialRecall,
			k.Thresholds(m), where, k.UsedBy)
	}
	if trained == 0 && len(kinds) > 1 {
		_, err = fmt.Fprintln(out, "No adjudicator was trained; review more proposals with `amass review proposals`.")
	}
	return err
}

// adjudicatorStatus reports, for the named kind or every kind, whether a
// model is trained (in the database or beside the journal), what it decides with, and how many
// labels are on hand. It opens no database and needs no model provider.
func adjudicatorStatus(j *review.Journal, kind string, out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}
	kinds, err := adjudicatorKinds(kind)
	if err != nil {
		return err
	}

	for i, k := range kinds {
		if i > 0 {
			_, _ = fmt.Fprintln(out)
		}
		m, where, err := k.Find(j)
		if err != nil {
			return err
		}
		positive, negative, model, err := k.LabelCounts(j)
		if err != nil {
			return err
		}

		_, _ = fmt.Fprintf(out, "%s: decides %s.\n", k.Name, k.Question)
		if m == nil {
			_, _ = fmt.Fprintf(out, "  Not trained (%s); %s decide without it.\n", where, k.UsedBy)
		} else {
			_, _ = fmt.Fprintf(out, "  Model %s in %s: %d features (%s), decides %s; used by %s.\n", m.ModelID,
				where, len(m.Features()), m.FeatureVersion, k.Thresholds(m), k.UsedBy)
		}
		if k.TwoSided {
			_, _ = fmt.Fprintf(out, "  %d labeled decision(s): %d %s, %d %s.", positive+negative, positive,
				k.Positive, negative, k.Negative)
		} else {
			_, _ = fmt.Fprintf(out, "  %d labeled decision(s): %d approved, %d rejected or retracted.",
				positive+negative, positive, negative)
		}
		if k.ModelExamples != nil {
			_, _ = fmt.Fprintf(out, " The main model's confident answers add %d to learn from; your decisions "+
				"alone judge the model.", model)
		}
		if n := positive + negative + model; n < k.MinExamples {
			_, _ = fmt.Fprintf(out, " %d more are needed to train.", k.MinExamples-n)
		}
		_, _ = fmt.Fprintln(out)
	}
	return nil
}
