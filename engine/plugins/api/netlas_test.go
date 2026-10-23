// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/caffix/stringset"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	"github.com/stretchr/testify/assert"
)

func TestNewNetlas(t *testing.T) {
	plugin := NewNetlas()
	assert.NotNil(t, plugin, "NewNetlas should not return nil")
	assert.Equal(t, "Netlas", plugin.Name(), "Plugin name should be Netlas")

	nl, ok := plugin.(*netlas)
	assert.True(t, ok, "Plugin should be of type *netlas")
	assert.NotNil(t, nl.source, "Plugin source should not be nil")
	assert.Equal(t, "Netlas", nl.source.Name, "Source name should be Netlas")
	assert.Equal(t, 80, nl.source.Confidence, "Source confidence should be 80")
	assert.NotNil(t, nl.rlimit, "Rate limiter should not be nil")

	assert.NotPanics(t, func() {
		nl.Stop()
	})
}

func TestNetlasJSONParsing(t *testing.T) {
	mockJSON := `{
		"count": 4,
		"took": 15,
		"items": [
			{
				"id": "api.example.com",
				"data": {
					"domain": "api.example.com"
				}
			},
			{
				"id": "*.wildcard.example.com",
				"data": {
					"domain": "*.wildcard.example.com"
				}
			},
			{
				"id": "portal.example.com",
				"data": {
					"domain": ""
				}
			},
			{
				"id": "test",
				"data": {
					"domain": "test"
				}
			}
		]
	}`

	var result struct {
		Count int `json:"count"`
		Items []struct {
			ID   string `json:"id"`
			Data struct {
				Domain string `json:"domain"`
			} `json:"data"`
		} `json:"items"`
	}

	err := json.Unmarshal([]byte(mockJSON), &result)
	assert.NoError(t, err, "JSON unmarshal should succeed")
	assert.Equal(t, 4, result.Count)
	assert.Equal(t, 4, len(result.Items))

	domain := "example.com"
	subs := stringset.New()
	defer subs.Close()

	for _, item := range result.Items {
		d := item.Data.Domain
		if d == "" {
			d = item.ID
		}
		d = amassdns.RemoveAsteriskLabel(d)
		if !strings.HasSuffix(d, "."+domain) && d != domain {
			d = d + "." + domain
		}
		d = strings.ToLower(strings.Trim(d, "."))
		if d != "" && d != domain {
			subs.Insert(d)
		}
	}

	parsedSlice := subs.Slice()
	assert.Contains(t, parsedSlice, "api.example.com")
	assert.Contains(t, parsedSlice, "wildcard.example.com")
	assert.Contains(t, parsedSlice, "portal.example.com")
	assert.Contains(t, parsedSlice, "test.example.com")
	assert.Equal(t, 4, len(parsedSlice))
}

func TestNetlasEmptyOrInvalidJSON(t *testing.T) {
	invalidJSON := `not valid json`
	var result struct {
		Count int `json:"count"`
		Items []struct {
			ID   string `json:"id"`
			Data struct {
				Domain string `json:"domain"`
			} `json:"data"`
		} `json:"items"`
	}

	err := json.Unmarshal([]byte(invalidJSON), &result)
	assert.Error(t, err)
}
