// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

// metered returns a copy of a whose model records usage, and the meter.
// A nil model stays nil so model-free queries keep failing closed.
func (a Agent) metered() (Agent, *llm.MeteredModel) {
	if a.Model == nil {
		return a, nil
	}
	if m, ok := a.Model.(*llm.MeteredModel); ok {
		return a, m
	}

	m := &llm.MeteredModel{Inner: a.Model}
	a.Model = m
	return a, m
}
