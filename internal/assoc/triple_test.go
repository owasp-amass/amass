// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assoc

import (
	"testing"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
	"github.com/stretchr/testify/assert"
)

func TestWildcardTriple(t *testing.T) {
	triple, err := ParseTriple("<*>-<*>-><*>")
	assert.NoError(t, err, "Failed to parse wildcard triple")
	assert.NotNil(t, triple, "Expected triple to be non-nil")
	assert.Equal(t, triple.Subject.Key, "*", "Expected subject to be wildcard")
	assert.Equal(t, triple.Subject.Type, oam.AssetType("*"), "Expected subject type to be wildcard")
	assert.Equal(t, triple.Predicate.Label, "*", "Expected predicate to be wildcard")
	assert.Equal(t, triple.Predicate.Type, oam.RelationType("*"), "Expected predicate type to be wildcard")
	assert.Equal(t, triple.Object.Key, "*", "Expected object to be wildcard")
	assert.Equal(t, triple.Object.Type, oam.AssetType("*"), "Expected object type to be wildcard")

	triple, err = ParseTriple("<fqdn:*>-<basicdnsrelation:dns_record>-><ipaddress:*>")
	assert.NoError(t, err, "Failed to parse a wildcard triple with specific types")
	assert.NotNil(t, triple, "Expected triple to be non-nil")
	assert.Equal(t, triple.Subject.Key, "*", "Expected subject key to be wildcard")
	assert.Equal(t, triple.Subject.Type, oam.FQDN, "Expected subject type to be FQDN")
	assert.Equal(t, triple.Predicate.Label, "dns_record", "Expected predicate label to be 'dns_record'")
	assert.Equal(t, triple.Predicate.Type, oam.BasicDNSRelation, "Expected predicate type to be BasicDNSRelation")
	assert.Equal(t, triple.Object.Key, "*", "Expected object to be wildcard")
	assert.Equal(t, triple.Object.Type, oam.IPAddress, "Expected object type to be IPAddress")

	triple, err = ParseTriple("<fqdn:owasp.org>-<*,since:2025-06-16>-><ipaddress:*,since:2025-06-16>")
	since, _ := time.Parse(time.DateOnly, "2025-06-16")
	assert.NoError(t, err, "Failed to parse a wildcard triple with specific types and since values")
	assert.NotNil(t, triple, "Expected triple to be non-nil")
	assert.Equal(t, triple.Subject.Key, "owasp.org", "Expected subject key to be wildcard")
	assert.Equal(t, triple.Subject.Type, oam.FQDN, "Expected subject type to be FQDN")
	assert.False(t, triple.Subject.IsWildcard(), "Expected subject to not be wildcard")
	assert.Equal(t, triple.Predicate.Label, "*", "Expected predicate label to be wildcard")
	assert.Equal(t, triple.Predicate.Type, oam.RelationType("*"), "Expected predicate type to be BasicDNSRelation")
	assert.Equal(t, triple.Predicate.Since, since, "Expected predicate since to match")
	assert.True(t, triple.Predicate.IsWildcard(), "Expected predicate to be wildcard")
	assert.Equal(t, triple.Object.Key, "*", "Expected object to be wildcard")
	assert.Equal(t, triple.Object.Type, oam.IPAddress, "Expected object type to be IPAddress")
	assert.Equal(t, triple.Object.Since, since, "Expected object since to match")
	assert.True(t, triple.Object.IsWildcard(), "Expected object to be wildcard")

	triple, err = ParseTriple("<fqdn:*>-<basicdnsrelation:*,header.rr_type:1>-><*,type:IPv4>")
	assert.NoError(t, err, "Failed to parse a wildcard triple with specific types and attributes")
	assert.NotNil(t, triple, "Expected triple to be non-nil")
	assert.True(t, triple.Subject.IsWildcard(), "Expected subject to be wildcard")
	assert.Equal(t, triple.Predicate.Label, "*", "Expected predicate label to be wildcard")
	assert.Equal(t, triple.Predicate.Type, oam.BasicDNSRelation, "Expected predicate type to be BasicDNSRelation")
	assert.True(t, triple.Predicate.IsWildcard(), "Expected predicate to be wildcard")
	assert.Equal(t, triple.Object.Key, "*", "Expected object to be wildcard")
	assert.Equal(t, triple.Object.Type, oam.AssetType("*"), "Expected object type to be wildcard")
	assert.False(t, triple.Object.IsWildcard(), "Expected object to not be wildcard")
}
