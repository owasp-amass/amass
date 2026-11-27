// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"os"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// setupMainModel gives the session's decisions to the main model, when one
// is configured and automatic attribution is not off:
//   - with attribution auto, the admissions into scope the evidence leaves
//     open (it makes automatic decisions the same way);
//   - the names in a person's field that may be an organization's, whose
//     answers are applied or kept as advice by the attribution mode. A
//     name-kind classifier trained on the review journal (amass ai train),
//     kept in the database or beside the journal's file, answers them
//     first, and is enough on its own without a model.
//
// The main model is never the document model: each is configured on its own.
func (s *Session) setupMainModel() {
	mode, journal, err := s.cfg.AIAttribution(os.LookupEnv)
	if err != nil || mode == config.AttributionOff {
		return
	}
	var base config.AISettings
	if s.cfg.AI != nil {
		base = *s.cfg.AI
	}
	settings, err := config.ResolveAISettings(base, os.LookupEnv)
	if err != nil {
		s.log.Warn("main model: " + err.Error())
		return
	}
	m, _, ok, err := ai.MainModel(settings, os.LookupEnv)
	if err != nil {
		s.log.Warn("main model: " + err.Error())
		ok = false
	}
	id := settings.Provider + "/" + settings.Model
	// One breaker for every decision the main model makes in this session:
	// after a few failures in a row it is not asked again, and what it would
	// have decided is left to the rules and to review.
	breaker := &ai.ModelBreaker{OnOpen: func(err error) {
		s.log.Warn("the main model is not asked again in this run; its decisions are left to the rules and "+
			"to review", "model", id, "error", err.Error())
	}}
	s.breaker = breaker

	names := &ai.NameKindDecider{Applies: settings.ClassifierApplies}
	if ok {
		names.Model = &ai.NameKindModel{Model: m, ModelID: id, Breaker: breaker}
	}
	if names.Classifier, err = ai.NameKindKind.LoadFor(review.OpenJournal(journal, s.db)); err != nil {
		s.log.Warn("name-kind classifier: " + err.Error())
	}
	if names.Model != nil || names.Classifier != nil {
		s.nameKinds = names
		s.log.Info("names that may be a person's or an organization's are decided by "+names.Name(),
			"classifier", names.Classifier != nil, "classifier_applies", names.Applies)
	}

	if sc, isScope := s.scope.(*scope.Scope); isScope && ok && mode == config.AttributionAuto {
		sc.SetAdmissionDeciders(&ai.AdmissionModel{Model: m, ModelID: id, Breaker: breaker})
		s.log.Info("admissions the evidence leaves open are decided by the main model", "model", id)
	}
}

// NameKinds implements et.Session: the decider of names that may be a
// person's or an organization's, or nil when there is none.
func (s *Session) NameKinds() et.NameKindDecider {
	return s.nameKinds
}
