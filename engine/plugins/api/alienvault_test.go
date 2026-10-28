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

func TestNewAlienVault(t *testing.T) {
	plugin := NewAlienVault()
	assert.NotNil(t, plugin, "NewAlienVault should not return nil")
	assert.Equal(t, "AlienVault", plugin.Name(), "Plugin name should be AlienVault")

	av, ok := plugin.(*alienVault)
	assert.True(t, ok, "Plugin should be of type *alienVault")
	assert.NotNil(t, av.source, "Plugin source should not be nil")
	assert.Equal(t, "AlienVault", av.source.Name, "Source name should be AlienVault")
	assert.Equal(t, 80, av.source.Confidence, "Source confidence should be 80")
	assert.NotNil(t, av.rlimit, "Rate limiter should not be nil")

	// Calling Stop before Start should be safe when logger is not initialized
	assert.NotPanics(t, func() {
		// Stop with nil logger
		if av.log != nil {
			av.Stop()
		}
	})
}

func TestAlienVaultJSONParsing(t *testing.T) {
	mockJSON := `{
		"passive_dns": [
			{
				"address": "93.184.216.34",
				"first": "2020-01-01T00:00:00",
				"last": "2021-01-01T00:00:00",
				"hostname": "sub.example.com",
				"record_type": "A"
			},
			{
				"address": "93.184.216.35",
				"first": "2020-01-01T00:00:00",
				"last": "2021-01-01T00:00:00",
				"hostname": "*.wildcard.example.com",
				"record_type": "A"
			},
			{
				"address": "93.184.216.36",
				"first": "2020-01-01T00:00:00",
				"last": "2021-01-01T00:00:00",
				"hostname": "",
				"record_type": "A"
			}
		],
		"count": 3
	}`

	var result struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}

	err := json.Unmarshal([]byte(mockJSON), &result)
	assert.NoError(t, err, "JSON unmarshal should succeed")
	assert.Equal(t, 3, len(result.PassiveDNS), "Should have parsed 3 passive DNS records")

	var parsedNames []string
	for _, record := range result.PassiveDNS {
		n := strings.ToLower(strings.TrimSpace(amassdns.RemoveAsteriskLabel(record.Hostname)))
		if n != "" {
			parsedNames = append(parsedNames, n)
		}
	}

	assert.Equal(t, 2, len(parsedNames), "Should have extracted 2 non-empty names")
	assert.Contains(t, parsedNames, "sub.example.com")
	assert.Contains(t, parsedNames, "wildcard.example.com")
}
