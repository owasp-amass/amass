// SPDX-License-Identifier: Apache-2.0
package oamrepo

import (
	"github.com/owasp-amass/open-asset-model/general"
	"testing"
)

func TestSourceIdentityExcludesConfidence(t *testing.T) {
	low := &general.SourceProperty{Source: "registrar-example", Confidence: 30}
	high := &general.SourceProperty{Source: "registrar-example", Confidence: 95}
	if source(low) != source(high) || source(low) != "registrar-example" {
		t.Fatalf("source identity incorrectly depends on confidence: %q vs %q", source(low), source(high))
	}
	other := &general.SimpleProperty{PropertyName: "registrar-example", PropertyValue: "yes"}
	if source(other) != "" {
		t.Fatal("non-source properties counted as independent provenance")
	}
}
