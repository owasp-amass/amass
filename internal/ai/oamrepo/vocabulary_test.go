// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai"
)

// Curated aliases must only name labels registered in the live OAM catalog;
// an alias for a non-existent label is silently dropped at runtime and
// misleads anyone maintaining the vocabulary.
func TestCuratedRelationLabelsExistInOAM(t *testing.T) {
	registered := map[string]bool{}
	for _, rel := range (Catalog{}).Relations() {
		registered[rel.Label] = true
	}
	for _, label := range ai.CuratedRelationLabels() {
		if !registered[label] {
			t.Errorf("curated alias label %q is not a registered OAM relation label", label)
		}
	}
}
