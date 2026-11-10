// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"strings"
	"testing"
)

func TestEmbeddedVocabularyLoads(t *testing.T) {
	if len(intentVocabulary["AutonomousSystem"]) == 0 || len(relationVocabulary) == 0 ||
		len(searchableFieldVocabulary) == 0 || len(investigationOperationVocabulary) == 0 {
		t.Fatal("embedded vocabulary did not load every section")
	}
}

func TestParseVocabularyRejectsEmptyEntries(t *testing.T) {
	for _, doc := range []string{
		`{"asset_types":{},"relations":{"node":["child"]},"search_fields":{"name":["name"]},"operations":{"x":["y"]}}`,
		`{"asset_types":{"FQDN":[]},"relations":{"node":["child"]},"search_fields":{"name":["name"]},` +
			`"operations":{"x":["y"]}}`,
	} {
		if _, err := parseVocabulary([]byte(doc)); err == nil || !strings.Contains(err.Error(), "AI vocabulary") {
			t.Errorf("accepted invalid vocabulary %s: %v", doc, err)
		}
	}
}
