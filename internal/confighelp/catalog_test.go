// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package confighelp

import (
	"reflect"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
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

// Every scope/seed, transformation and data source field, and every
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
	for _, name := range yamlFields(reflect.TypeOf(config.DataSource{})) {
		has("datasources." + name)
	}

	// Options are parsed from a map, not struct fields, so the documented
	// keys are checked explicitly.
	for _, key := range []string{"datasources", "database", "engine", "resolvers", "bruteforce", "alterations",
		"default_transform_values", "minimum_ttl", "probe_pace_ms", "probe_jitter_ms"} {
		has("options." + key)
	}

	has("active")
	has("rigid_boundaries")
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
