// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"reflect"
	"sort"
	"testing"
)

func TestConfigSetResolvers(t *testing.T) {
	type fields struct {
		config *Config
	}
	type args struct {
		resolvers []string
	}

	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name:   "success",
			fields: fields{config: &Config{}},
			args: args{
				resolvers: []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fields.config.SetResolvers(tt.args.resolvers...)

			sort.Strings(tt.fields.config.Resolvers)
			if !reflect.DeepEqual(tt.args.resolvers, tt.fields.config.Resolvers) {
				t.Errorf("SetResolvers() = %v, want %v",
					tt.args.resolvers, tt.fields.config.Resolvers)
			}
		})
	}
}

func TestLoadResolverSettings(t *testing.T) {
	c := NewConfig()
	c.Options = make(map[string]interface{})

	// Test with no resolvers in options
	err := c.loadResolverSettings(c)
	if err != nil {
		t.Errorf("Expected no error when no resolvers are provided, got an error")
	}

	// Test with incorrect type in resolvers
	c.Options["resolvers"] = "Not a slice"
	err = c.loadResolverSettings(c)
	if err == nil {
		t.Errorf("Expected an error when resolvers are not a slice, got nil")
	}

	// Test with valid resolvers
	c.Options["resolvers"] = []interface{}{"192.0.2.1", "192.0.2.2"}
	err = c.loadResolverSettings(c)
	if err != nil {
		t.Errorf("Got an error when valid resolvers are provided, expected nil. Error: %v", err)
	}

	// Test with valid resolvers including duplicates
	c.Options["resolvers"] = []interface{}{"192.0.2.1", "192.0.2.2", "192.0.2.1"}
	err = c.loadResolverSettings(c)
	if err != nil {
		t.Errorf("Got an error when valid resolvers (including duplicates) are provided, expected nil. Error: %v", err)
	}

	// Test with valid file path with resolvers
	_ = os.WriteFile("testResolvers.txt", []byte("192.0.2.3\n192.0.2.4"), 0644)
	c.Options["resolvers"] = []interface{}{"192.0.2.1", "192.0.2.2", "testResolvers.txt"}
	err = c.loadResolverSettings(c)
	if err != nil {
		t.Errorf("Got an error when valid resolvers and valid file path are provided, expected nil. Error: %v", err)
	}
	defer os.Remove("testResolvers.txt")
}

func TestLoadResolversFromFile(t *testing.T) {
	c := NewConfig()

	// Test with non-existing file
	_, err := c.loadResolversFromFile("nonExistingFile.txt")
	if err == nil {
		t.Errorf("Expected an error when file does not exist, got nil")
	}

	// Test with invalid IPs in file
	_ = os.WriteFile("invalidResolvers.txt", []byte("192.0.2.300\ninvalidIP"), 0644)
	_, err = c.loadResolversFromFile("invalidResolvers.txt")
	if err == nil {
		t.Errorf("Expected an error when file contains invalid IPs, got nil")
	}
	os.Remove("invalidResolvers.txt")

	// Test with valid IPs in file
	_ = os.WriteFile("validResolvers.txt", []byte("192.0.2.3\n192.0.2.4"), 0644)
	resolvers, err := c.loadResolversFromFile("validResolvers.txt")
	if err != nil {
		t.Errorf("Got an error when file contains valid IPs, expected nil. Error: %v", err)
	}

	if len(resolvers) != 2 {
		t.Errorf("Expected 2 resolvers, got %v", len(resolvers))
	}

	if resolvers[0] != "192.0.2.3" || resolvers[1] != "192.0.2.4" {
		t.Errorf("Resolvers do not match expected values. Got: %v", resolvers)
	}
	os.Remove("validResolvers.txt")
}
