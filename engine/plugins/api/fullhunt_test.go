// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"strings"
	"testing"

	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	"github.com/stretchr/testify/assert"
)

func TestNewFullHunt(t *testing.T) {
	plugin := NewFullHunt()
	assert.NotNil(t, plugin, "NewFullHunt should not return nil")
	assert.Equal(t, "FullHunt", plugin.Name(), "Plugin name should be FullHunt")

	fh, ok := plugin.(*fullhunt)
	assert.True(t, ok, "Plugin should be of type *fullhunt")
	assert.NotNil(t, fh.source, "Plugin source should not be nil")
	assert.Equal(t, "FullHunt", fh.source.Name, "Source name should be FullHunt")
	assert.Equal(t, 80, fh.source.Confidence, "Source confidence should be 80")
	assert.NotNil(t, fh.rlimit, "Rate limiter should not be nil")

	assert.NotPanics(t, func() {
		fh.Stop()
	})
}

func TestFullHuntJSONParsing(t *testing.T) {
	mockJSON := `{
		"status": 200,
		"domain": "example.com",
		"hosts": [
			"api.example.com",
			"*.wildcard.example.com"
		],
		"subdomains": [
			"portal",
			"test.example.com"
		],
		"records": [
			{
				"host": "mail.example.com"
			},
			{
				"host": ""
			}
		]
	}`

	var result struct {
		Hosts      []string `json:"hosts"`
		Subdomains []string `json:"subdomains"`
		Records    []struct {
			Host string `json:"host"`
		} `json:"records"`
	}

	err := json.Unmarshal([]byte(mockJSON), &result)
	assert.NoError(t, err, "JSON unmarshal should succeed")
	assert.Equal(t, 2, len(result.Hosts))
	assert.Equal(t, 2, len(result.Subdomains))
	assert.Equal(t, 2, len(result.Records))

	domain := "example.com"
	var candidates []string
	candidates = append(candidates, result.Hosts...)
	candidates = append(candidates, result.Subdomains...)
	for _, rec := range result.Records {
		if rec.Host != "" {
			candidates = append(candidates, rec.Host)
		}
	}

	var parsedNames []string
	for _, item := range candidates {
		item = amassdns.RemoveAsteriskLabel(item)
		if !strings.HasSuffix(item, "."+domain) && item != domain {
			item = item + "." + domain
		}
		item = strings.ToLower(strings.Trim(item, "."))
		if item != "" && item != domain {
			parsedNames = append(parsedNames, item)
		}
	}

	assert.Contains(t, parsedNames, "api.example.com")
	assert.Contains(t, parsedNames, "wildcard.example.com")
	assert.Contains(t, parsedNames, "portal.example.com")
	assert.Contains(t, parsedNames, "test.example.com")
	assert.Contains(t, parsedNames, "mail.example.com")
	assert.Equal(t, 5, len(parsedNames))
}

func TestFullHuntEmptyOrInvalidJSON(t *testing.T) {
	invalidJSON := `not valid json`
	var result struct {
		Hosts      []string `json:"hosts"`
		Subdomains []string `json:"subdomains"`
		Records    []struct {
			Host string `json:"host"`
		} `json:"records"`
	}

	err := json.Unmarshal([]byte(invalidJSON), &result)
	assert.Error(t, err)
}
