// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var reachYAML = []byte(`
transformations:
  default:
    reach: footprint
  FQDN->ALL:
    reach: connected
    hops: 2
  FQDN->IPAddress:
  FQDN->Netblock:
    reach: footprint
  FQDN->BruteForcing:
    reach: scope
  Organization->ALL:
  Organization->GLEIF:
    reach: any
`)

func TestTransformationReach(t *testing.T) {
	c, err := prepareConfig(reachYAML)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		from, plugin string
		tos          []string
		reach        string
		hops         int
	}{
		// a transformation naming the plugin wins
		{"FQDN", "BruteForcing", []string{"FQDN"}, ReachScope, 0},
		// a target type without a reach takes ALL's
		{"FQDN", "DNS", []string{"IPAddress"}, ReachConnected, 2},
		// of several target types, the narrowest reach
		{"FQDN", "DNS", []string{"IPAddress", "Netblock"}, ReachFootprint, 0},
		{"Organization", "GLEIF", nil, ReachAny, 0},
		// nothing set for the type: transformations.default
		{"Organization", "Aviato", []string{"Organization"}, ReachFootprint, 0},
	} {
		reach, hops := c.TransformationReach(tc.from, tc.plugin, tc.tos...)
		if reach != tc.reach || hops != tc.hops {
			t.Errorf("%s via %s %v: %s %d, want %s %d", tc.from, tc.plugin, tc.tos, reach, hops, tc.reach, tc.hops)
		}
	}

	// A configuration that sets no reach gets the footprint policy, and says
	// it has none.
	plain, err := prepareConfig(validYAML)
	if err != nil {
		t.Fatal(err)
	}
	if reach, _ := plain.TransformationReach("FQDN", "DNS", "IPAddress"); reach != ReachFootprint {
		t.Errorf("no policy: reach %s, want footprint", reach)
	}
	if plain.HasExpansionPolicy() || !c.HasExpansionPolicy() {
		t.Error("HasExpansionPolicy")
	}

	// The strict policy holds a run to its given scope and admits nothing.
	if !plain.Widens() {
		t.Error("a configuration with the default confidence widens")
	}
	plain.ApplyStrictPolicy()
	if reach, _ := plain.TransformationReach("FQDN", "DNS", "IPAddress"); reach != ReachScope || plain.Widens() {
		t.Errorf("strict policy: reach %s, widens %v", reach, plain.Widens())
	}
	removed := NewConfig()
	removed.Options = map[string]interface{}{"rigid_boundaries": true}
	if err := removed.refuseRemovedSettings(removed); err == nil {
		t.Error("the removed rigid_boundaries option was accepted")
	}
}

func TestReachValidation(t *testing.T) {
	for yaml, want := range map[string]string{
		"transformations:\n  FQDN->ALL:\n    reach: everywhere\n":             "reach must be",
		"transformations:\n  FQDN->ALL:\n    reach: scope\n    hops: 2\n":     "hops applies only",
		"transformations:\n  FQDN->ALL:\n    reach: connected\n    hops: 9\n": "hops must be",
		"transformations:\n  default:\n    reach: wide\n":                     "transformations.default: reach must be",
		"transformations:\n  default:\n    exclude: [FQDN]\n":                 "exclude applies",
		"options:\n  default_transform_values:\n    reach: footprint\n":       "moved to transformations.default",
	} {
		if _, err := prepareConfig([]byte(yaml)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want %q", yaml, err, want)
		}
	}
}

// The example policies in resources/examples load and validate.
func TestExamplePolicies(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "resources", "examples", "policy-*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no example policies: %v", err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		c, err := prepareConfig(data)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if reach, _ := c.TransformationReach("FQDN", "DNS", "IPAddress"); reach == "" {
			t.Errorf("%s: no reach for FQDN->DNS", f)
		}
	}
}

func TestMatchConfidence(t *testing.T) {
	for conf, want := range map[int]int{NeverAdmit: 100, 100: 100, 50: 50, 0: 0} {
		if got := MatchConfidence(conf); got != want {
			t.Errorf("MatchConfidence(%d) = %d, want %d", conf, got, want)
		}
	}
}

// The defaults reach the engine with the rest of the configuration, so a
// policy set only there (reach: scope) holds in the engine's sessions too.
func TestDefaultTransformationTravels(t *testing.T) {
	c, err := prepareConfig([]byte("transformations:\n  default:\n    reach: scope\n    confidence: 101\n  FQDN->ALL:\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Transformations[DefaultTransformationKey]; ok {
		t.Fatal("the defaults were left among the transformations")
	}

	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var engine Config
	if err := json.Unmarshal(raw, &engine); err != nil {
		t.Fatal(err)
	}
	if engine.DefaultTransformations == nil || engine.DefaultTransformations.Reach != ReachScope ||
		engine.Widens() {
		t.Errorf("the engine's defaults: %+v", engine.DefaultTransformations)
	}
}
