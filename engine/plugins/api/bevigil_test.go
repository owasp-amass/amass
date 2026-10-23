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

func TestNewBeVigil(t *testing.T) {
	plugin := NewBeVigil()
	assert.NotNil(t, plugin, "NewBeVigil should not return nil")
	assert.Equal(t, "BeVigil", plugin.Name(), "Plugin name should be BeVigil")

	bv, ok := plugin.(*bevigil)
	assert.True(t, ok, "Plugin should be of type *bevigil")
	assert.NotNil(t, bv.source, "Plugin source should not be nil")
	assert.Equal(t, "BeVigil", bv.source.Name, "Source name should be BeVigil")
	assert.Equal(t, 80, bv.source.Confidence, "Source confidence should be 80")
	assert.NotNil(t, bv.rlimit, "Rate limiter should not be nil")

	assert.NotPanics(t, func() {
		bv.Stop()
	})
}

func TestBeVigilJSONParsing(t *testing.T) {
	mockJSON := `{
		"domain": "example.com",
		"subdomains": [
			"api.example.com",
			"*.wildcard.example.com",
			"portal",
			"test.example.com",
			""
		]
	}`

	var result struct {
		Domain     string   `json:"domain"`
		Subdomains []string `json:"subdomains"`
	}

	err := json.Unmarshal([]byte(mockJSON), &result)
	assert.NoError(t, err, "JSON unmarshal should succeed")
	assert.Equal(t, "example.com", result.Domain)
	assert.Equal(t, 5, len(result.Subdomains))

	domain := "example.com"
	var parsedNames []string
	for _, sub := range result.Subdomains {
		sub = amassdns.RemoveAsteriskLabel(sub)
		if !strings.HasSuffix(sub, "."+domain) && sub != domain {
			sub = sub + "." + domain
		}
		sub = strings.ToLower(strings.Trim(sub, "."))
		if sub != "" && sub != domain {
			parsedNames = append(parsedNames, sub)
		}
	}

	assert.Contains(t, parsedNames, "api.example.com")
	assert.Contains(t, parsedNames, "wildcard.example.com")
	assert.Contains(t, parsedNames, "portal.example.com")
	assert.Contains(t, parsedNames, "test.example.com")
	assert.Equal(t, 4, len(parsedNames))
}

func TestBeVigilEmptyOrInvalidJSON(t *testing.T) {
	invalidJSON := `not valid json`
	var result struct {
		Domain     string   `json:"domain"`
		Subdomains []string `json:"subdomains"`
	}

	err := json.Unmarshal([]byte(invalidJSON), &result)
	assert.Error(t, err)
}
