// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

var validyaml = []byte(`
options:
   active: true
`)

var validyaml2 = []byte(`
options:
   active: false
`)

var invalidyaml = []byte(`
options:
   active: "true"
`)

func TestActive(t *testing.T) {
	c := NewConfig()

	err := yaml.Unmarshal(validyaml, c)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Test case 1: MarshalJSON returns the expected JSON bytes
	t.Run("TestActive returns the expected JSON bytes", func(t *testing.T) {
		expected := []byte(`{"seed":{},"scope":{"ports":[21,22,25,80,110,143,443,465,587,993,995,2375,2379,5984,6443,8000,8080,8443,8500,8888,9200,9443,10000,10250]},"options":{"active":true},"default_transformation":{"priority":5,"confidence":50,"ttl":1440},"recursive":true,"min_for_recursive":1,"flip_words":true,"flip_numbers":true,"add_words":true,"add_numbers":true,"min_for_word_flip":2,"edit_distance":1,"active":true,"minimum_ttl":1440,"resolvers":null,"datasource_config":{},"transformations":{}}
`)
		_ = c.loadActiveSettings(c)
		got, err := c.JSON()
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("Unexpected JSON bytes.\nExpected: %s\nGot: %s", expected, got)
		}

	})

	t.Run("TestActive returns the expected JSON bytes when active isnt provided", func(t *testing.T) {
		c := NewConfig()
		expected := []byte(`{"seed":{},"scope":{"ports":[21,22,25,80,110,143,443,465,587,993,995,2375,2379,5984,6443,8000,8080,8443,8500,8888,9200,9443,10000,10250]},"default_transformation":{"priority":5,"confidence":50,"ttl":1440},"recursive":true,"min_for_recursive":1,"flip_words":true,"flip_numbers":true,"add_words":true,"add_numbers":true,"min_for_word_flip":2,"edit_distance":1,"minimum_ttl":1440,"resolvers":null,"datasource_config":{},"transformations":{}}
`)

		got, err := c.JSON()
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("Unexpected JSON bytes.\nExpected: %s\nGot: %s", expected, got)
		}

	})

	t.Run("TestActive returns the expected JSON bytes when active is false", func(t *testing.T) {
		err := yaml.Unmarshal(validyaml2, c)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		expected := []byte(`{"seed":{},"scope":{"ports":[21,22,25,80,110,143,443,465,587,993,995,2375,2379,5984,6443,8000,8080,8443,8500,8888,9200,9443,10000,10250]},"options":{"active":false},"default_transformation":{"priority":5,"confidence":50,"ttl":1440},"recursive":true,"min_for_recursive":1,"flip_words":true,"flip_numbers":true,"add_words":true,"add_numbers":true,"min_for_word_flip":2,"edit_distance":1,"minimum_ttl":1440,"resolvers":null,"datasource_config":{},"transformations":{}}
`)

		_ = c.loadActiveSettings(c)
		got, err := c.JSON()
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("Unexpected JSON bytes.\nExpected: %s\nGot: %s", expected, got)
		}

	})

	t.Run("TestActive fails to parse non-bool active setting", func(t *testing.T) {
		c := NewConfig()
		err := yaml.Unmarshal(invalidyaml, c)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		err = c.loadActiveSettings(c)
		if err == nil {
			t.Errorf("Expected error, got nil")
		}
	})
}
