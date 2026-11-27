// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package breachsources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalogLoads(t *testing.T) {
	sources := Sources()
	require.NotEmpty(t, sources)
	for _, s := range sources {
		assert.NotEmpty(t, s.Key)
		assert.NotEmpty(t, s.EmailURL)
		assert.NotEmpty(t, s.Source)
		if s.EmailFormat != "" {
			assert.NotNilf(t, parsers[s.EmailFormat], "source %s email format %q has no parser", s.Key, s.EmailFormat)
		}
		if s.DomainFormat != "" {
			assert.NotNilf(t, parsers[s.DomainFormat], "source %s domain format %q has no parser", s.Key, s.DomainFormat)
		}
	}

	xon, ok := SourceByKey("xposedornot")
	require.True(t, ok)
	assert.True(t, xon.Free)
	assert.False(t, xon.RequiresKey)
}

func TestParseXONAnalytics(t *testing.T) {
	data := []byte(`{
		"BreachesSummary": {"site": "Adobe;Dropbox"},
		"ExposedBreaches": {"breaches_details": [
			{"breach": "Adobe", "xposed_data": "Email addresses;Password hints;Passwords", "xposed_date": "2013", "verified": "Yes"},
			{"breach": "Dropbox", "xposed_data": "Email addresses;Passwords", "xposed_date": "2012", "verified": "No"}
		]},
		"BreachMetrics": {"risk": [{"risk_score": 7}]}
	}`)

	got, err := Parse("xon_analytics", data)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "Adobe", got[0].Breach)
	assert.Equal(t, "2013", got[0].Date)
	assert.True(t, got[0].Verified)
	assert.Equal(t, []string{"Email addresses", "Password hints", "Passwords"}, got[0].DataClasses)
	assert.False(t, got[1].Verified)
}

func TestParseXONAnalyticsNotFound(t *testing.T) {
	got, err := Parse("xon_analytics", []byte(`{"Error": "Not found"}`))
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestParseHIBPAccount(t *testing.T) {
	data := []byte(`[
		{"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04",
			"DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"], "IsVerified": true},
		{"Name": "Gawker", "Title": "Gawker", "BreachDate": "2010-12-11",
			"DataClasses": ["Email addresses", "Passwords", "Usernames"], "IsVerified": true}
	]`)

	got, err := Parse("hibp_account", data)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "Adobe", got[0].Breach)
	assert.Equal(t, "2013-10-04", got[0].Date)
	assert.True(t, got[0].Verified)
	assert.Contains(t, got[0].DataClasses, "Passwords")
}

func TestParseUnknownFormat(t *testing.T) {
	_, err := Parse("nope", []byte(`{}`))
	assert.Error(t, err)
}
