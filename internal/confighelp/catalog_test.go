// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package confighelp

import (
	"reflect"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/resources"
	"gopkg.in/yaml.v3"
)

func yamlFields(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("yaml")
		name, _, _ := strings.Cut(tag, ",")
		if name != "" && name != "-" {
			out = append(out, name)
		}
	}

	return out
}

// Every scope/seed, transformation, data source and AI field, and every
// documented option, must be described in the catalog, so the assistant
// never meets a setting it cannot explain. A new config field fails this
// until it is cataloged.
func TestCatalogCoversTheConfig(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	has := func(path string) {
		t.Helper()
		if _, ok := c.Lookup(path); !ok {
			t.Errorf("the catalog has no entry for %q", path)
		}
	}

	for _, name := range yamlFields(reflect.TypeOf(config.Scope{})) {
		has("scope." + name)
	}
	for _, name := range yamlFields(reflect.TypeOf(config.Transformation{})) {
		has("transformations." + name)
	}
	has("transformations." + config.DefaultTransformationKey)
	for _, name := range yamlFields(reflect.TypeOf(config.DataSource{})) {
		has("datasources." + name)
	}
	for _, name := range yamlFields(reflect.TypeOf(config.AISettings{})) {
		if name != "documents" && name != "contributions" {
			has("options.ai." + name)
		}
	}
	for _, name := range yamlFields(reflect.TypeOf(config.ContributionSettings{})) {
		has("options.ai.contributions." + name)
	}
	for _, name := range yamlFields(reflect.TypeOf(config.DocumentModelSettings{})) {
		has("options.ai.documents." + name)
	}

	// Options are parsed from a map, not struct fields, so the documented
	// keys are checked explicitly.
	for _, key := range []string{"datasources", "database", "engine", "resolvers", "trusted_resolvers", "interface",
		"active_route", "active_udp_route", "bruteforce", "alterations", "minimum_ttl",
		"probe_pace_ms", "probe_jitter_ms", "background_hold"} {
		has("options." + key)
	}

	has("active")
}

func TestCatalogLookupsAndSections(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	f, ok := c.Lookup("options.probe_pace_ms")
	if !ok || f.Section != "options" || f.Default == "" {
		t.Errorf("probe_pace_ms = %+v (ok=%v)", f, ok)
	}
	if _, ok := c.Lookup("scope.nonexistent"); ok {
		t.Error("an unknown path should not resolve")
	}

	for _, want := range []string{"seed", "scope", "options", "transformations", "datasources", "ai"} {
		if _, ok := c.Sections[want]; !ok {
			t.Errorf("the catalog is missing the %q section", want)
		}
	}
	if len(c.SectionFields("scope")) == 0 {
		t.Error("the scope section has no fields")
	}
}

// Every option and transformations key the default configuration file sets
// is in the catalog, so the file cannot gain a setting the assistant's
// config tools cannot explain.
func TestCatalogCoversTheDefaultConfig(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	data, err := resources.GetResourceFileData("config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	var file struct {
		Options         map[string]any `yaml:"options"`
		Transformations map[string]any `yaml:"transformations"`
	}
	if err := yaml.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Options) == 0 {
		t.Fatal("the default configuration sets no options")
	}
	for key := range file.Options {
		if _, ok := c.Lookup("options." + key); !ok {
			t.Errorf("the catalog has no entry for options.%s, which the default configuration sets", key)
		}
	}
	if _, ok := file.Transformations[config.DefaultTransformationKey]; !ok {
		t.Error("the default configuration has no transformations.default")
	} else if _, ok := c.Lookup("transformations." + config.DefaultTransformationKey); !ok {
		t.Error("the catalog has no entry for transformations.default")
	}
}
