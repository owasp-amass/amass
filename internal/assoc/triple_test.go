// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assoc

import (
	"fmt"
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

func TestParseNode(t *testing.T) {
	// no angle brackets should result in an error
	n, err := parseNode("fqdn:*")
	assert.Error(t, err, "Failed to detect missing angle brackets")
	assert.Nil(t, n, "Returned a node without angle brackets")

	// no opening angle bracket should result in an error
	n, err = parseNode("fqdn:*>")
	assert.Error(t, err, "Failed to detect a missing opening angle bracket")
	assert.Nil(t, n, "Returned a node without an opening angle bracket")

	// no closing angle bracket should result in an error
	n, err = parseNode("<fqdn:*")
	assert.Error(t, err, "Failed to detect a missing closing angle bracket")
	assert.Nil(t, n, "Returned a node without a closing angle bracket")

	// test that the expected since value is correctly parsed out
	atype := "fqdn"
	key := "owasp.org"
	since, _ := time.Parse(time.DateOnly, "2025-06-22")
	pstr := fmt.Sprintf("<%s:%s,since:%s>", string(atype), key, since.Format(time.DateOnly))
	n, err = parseNode(pstr)
	assert.NoError(t, err, "Failed to parse properly formed node")
	assert.NotNil(t, n, "Returned nil when parsing a properly formed node")
	assert.Equal(t, n.Type, oam.FQDN, "Failed to return the correct node type")
	assert.Equal(t, n.Key, key, "Failed to parse the provided node key")
	assert.Equal(t, n.Since, since, "Expected node since to match")

	// incorrectly formatted date should result in an error
	pstr = fmt.Sprintf("<%s:%s,since:2025-1-40", string(atype), key)
	n, err = parseNode(pstr)
	assert.Error(t, err, "Failed to detect the malformed since date")
	assert.Nil(t, n, "Returned a node without a properly formatted date")

	// test that the expected attribute value is correctly parsed out
	atype = "ipaddress"
	key = "72.237.4.113"
	pstr = fmt.Sprintf("<%s:%s,type:IPv4>", string(atype), key)
	n, err = parseNode(pstr)
	assert.NoError(t, err, "Failed to parse properly formed node")
	assert.NotNil(t, n, "Returned nil when parsing a properly formed node")
	assert.Equal(t, n.Type, oam.IPAddress, "Failed to return the correct node type")
	assert.Equal(t, n.Key, key, "Failed to parse the provided node key")
	assert.Equal(t, n.Attributes["type"].Value, "IPv4", "Expected node attribute to match")

	// test that the property is correctly parsed out
	pstr = fmt.Sprintf("<%s:%s,prop:[sourceproperty:*,confidence:100]>", string(atype), key)
	n, err = parseNode(pstr)
	assert.NoError(t, err, "Failed to parse properly formed node")
	assert.NotNil(t, n, "Returned nil when parsing a properly formed node")
	assert.Equal(t, n.Type, oam.IPAddress, "Failed to return the correct node type")
	assert.Equal(t, n.Key, key, "Failed to parse the provided node key")
	assert.Equal(t, n.Properties[0].Type, oam.SourceProperty, "Failed to return the correct property type")
	assert.Equal(t, n.Properties[0].Name, "*", "Failed to parse the provided property name")
	assert.Equal(t, n.Properties[0].Attributes["confidence"].Value, "100", "Expected property attribute to match")

	// test that the regexps are being correctly parsed out
	key = "#/72.237.4.*/#"
	attre := "#/IPv./#"
	pstr = fmt.Sprintf("<%s:%s,type:%s>", string(atype), key, attre)
	n, err = parseNode(pstr)
	assert.NoError(t, err, "Failed to parse properly formed node")
	assert.NotNil(t, n, "Returned nil when parsing a properly formed node")
	assert.Equal(t, n.Type, oam.IPAddress, "Failed to return the correct node type")
	assert.Equal(t, n.Key, key, "Failed to parse the provided node key")
	assert.NotNil(t, n.Regexp, "Expected the node regexp to be compiled and set")
	assert.Equal(t, n.Attributes["type"].Value, attre, "Expected node attribute to match")
	assert.NotNil(t, n.Attributes["type"].Regexp, "Expected the attribute regexp to be compiled and set")

	// incorrectly formatted node regexp should result in an error
	n, err = parseNode("<ipaddress:#/foo(?!bar)/#>")
	assert.Error(t, err, "Failed to detect a node regexp that shouldn't compile")
	assert.Nil(t, n, "Returned a node when the node regexp shouldn't compile")

	// incorrectly formatted node attribute regexp should result in an error
	n, err = parseNode("<*,type:#/foo(?!bar)/#>")
	assert.Error(t, err, "Failed to detect an attribute regexp that shouldn't compile")
	assert.Nil(t, n, "Returned a node when the attribute regexp shouldn't compile")
}

func TestParsePredicate(t *testing.T) {
	// no angle brackets should result in an error
	p, err := parsePredicate("simplerelation:*")
	assert.Error(t, err, "Failed to detect missing angle brackets")
	assert.Nil(t, p, "Returned a predicate without angle brackets")

	// no opening angle bracket should result in an error
	p, err = parsePredicate("simplerelation:*>")
	assert.Error(t, err, "Failed to detect a missing opening angle bracket")
	assert.Nil(t, p, "Returned a predicate without an opening angle bracket")

	// no closing angle bracket should result in an error
	p, err = parsePredicate("<simplerelation:*")
	assert.Error(t, err, "Failed to detect a missing closing angle bracket")
	assert.Nil(t, p, "Returned a predicate without a closing angle bracket")

	// test that the expected since value is correctly parsed out
	rtype := "simplerelation"
	label := "node"
	since, _ := time.Parse(time.DateOnly, "2025-06-21")
	pstr := fmt.Sprintf("<%s:%s,since:%s>", string(rtype), label, since.Format(time.DateOnly))
	p, err = parsePredicate(pstr)
	assert.NoError(t, err, "Failed to parse properly formed predicate")
	assert.NotNil(t, p, "Returned nil when parsing a properly formed predicate")
	assert.Equal(t, p.Type, oam.SimpleRelation, "Failed to return the correct predicate type")
	assert.Equal(t, p.Label, label, "Failed to parse the provided predicate label")
	assert.Equal(t, p.Since, since, "Expected predicate since to match")

	// incorrectly formatted date should result in an error
	pstr = fmt.Sprintf("<%s:%s,since:2025-1-40", string(rtype), label)
	p, err = parsePredicate(pstr)
	assert.Error(t, err, "Failed to detect the malformed since date")
	assert.Nil(t, p, "Returned a predicate without a properly formatted date")

	// test that the expected attribute value is correctly parsed out
	rtype = "basicdnsrelation"
	label = "dns_record"
	pstr = fmt.Sprintf("<%s:%s,header.rr_type:2>", string(rtype), label)
	p, err = parsePredicate(pstr)
	assert.NoError(t, err, "Failed to parse properly formed predicate")
	assert.NotNil(t, p, "Returned nil when parsing a properly formed predicate")
	assert.Equal(t, p.Type, oam.BasicDNSRelation, "Failed to return the correct predicate type")
	assert.Equal(t, p.Label, label, "Failed to parse the provided predicate label")
	assert.Equal(t, p.Attributes["header.rr_type"].Value, "2", "Expected predicate attribute to match")

	// test that the property is correctly parsed out
	pstr = fmt.Sprintf("<%s:%s,prop:[sourceproperty:*,confidence:100]>", string(rtype), label)
	p, err = parsePredicate(pstr)
	assert.NoError(t, err, "Failed to parse properly formed predicate")
	assert.NotNil(t, p, "Returned nil when parsing a properly formed predicate")
	assert.Equal(t, p.Type, oam.BasicDNSRelation, "Failed to return the correct predicate type")
	assert.Equal(t, p.Label, label, "Failed to parse the provided predicate label")
	assert.Equal(t, p.Properties[0].Type, oam.SourceProperty, "Failed to return the correct property type")
	assert.Equal(t, p.Properties[0].Name, "*", "Failed to parse the provided property name")
	assert.Equal(t, p.Properties[0].Attributes["confidence"].Value, "100", "Expected property attribute to match")

	// test that the regexps are being correctly parsed out
	label = "#/dns.*/#"
	attre := "#/1|28/#"
	pstr = fmt.Sprintf("<%s:%s,header.rr_type:%s>", string(rtype), label, attre)
	p, err = parsePredicate(pstr)
	assert.NoError(t, err, "Failed to parse properly formed predicate")
	assert.NotNil(t, p, "Returned nil when parsing a properly formed predicate")
	assert.Equal(t, p.Type, oam.BasicDNSRelation, "Failed to return the correct predicate type")
	assert.Equal(t, p.Label, label, "Failed to parse the provided predicate key")
	assert.NotNil(t, p.Regexp, "Expected the predicate regexp to be compiled and set")
	assert.Equal(t, p.Attributes["header.rr_type"].Value, attre, "Expected predicate attribute to match")
	assert.NotNil(t, p.Attributes["header.rr_type"].Regexp, "Expected the attribute regexp to be compiled and set")

	// incorrectly formatted predicate regexp should result in an error
	p, err = parsePredicate("<simplerelation:#/foo(?!bar)/#>")
	assert.Error(t, err, "Failed to detect a predicate regexp that shouldn't compile")
	assert.Nil(t, p, "Returned a predicate when the predicate regexp shouldn't compile")

	// incorrectly formatted predicate attribute regexp should result in an error
	p, err = parsePredicate("<*,name:#/foo(?!bar)/#>")
	assert.Error(t, err, "Failed to detect an attribute regexp that shouldn't compile")
	assert.Nil(t, p, "Returned a predicate when the attribute regexp shouldn't compile")
}

func TestParseProperty(t *testing.T) {
	// no square brackets should result in an error
	p, err := parseProperty("sourceproperty:*")
	assert.Error(t, err, "Failed to detect missing square brackets")
	assert.Nil(t, p, "Returned a property without square brackets")

	// no opening square bracket should result in an error
	p, err = parseProperty("sourceproperty:*]")
	assert.Error(t, err, "Failed to detect a missing opening square bracket")
	assert.Nil(t, p, "Returned a property without an opening square bracket")

	// no closing square bracket should result in an error
	p, err = parseProperty("[sourceproperty:*")
	assert.Error(t, err, "Failed to detect a missing closing square bracket")
	assert.Nil(t, p, "Returned a property without a closing square bracket")

	// test that the expected since value is correctly parsed out
	ptype := "sourceproperty"
	pname := "hackertarget"
	since, _ := time.Parse(time.DateOnly, "2025-06-21")
	pstr := fmt.Sprintf("[%s:%s,since:%s]", string(ptype), pname, since.Format(time.DateOnly))
	p, err = parseProperty(pstr)
	assert.NoError(t, err, "Failed to parse properly formed property")
	assert.NotNil(t, p, "Returned nil when parsing a properly formed property")
	assert.Equal(t, p.Type, oam.SourceProperty, "Failed to return the correct property type")
	assert.Equal(t, p.Name, pname, "Failed to parse the provided property name")
	assert.Equal(t, p.Since, since, "Expected property since to match")

	// incorrectly formatted date should result in an error
	pstr = fmt.Sprintf("<%s:%s,since:2025-1-40", string(ptype), pname)
	p, err = parseProperty(pstr)
	assert.Error(t, err, "Failed to detect the malformed since date")
	assert.Nil(t, p, "Returned a property without a properly formatted date")

	// test that the expected attribute value is correctly parsed out
	ptype = "dnsrecordproperty"
	pname = "dns_record"
	pstr = fmt.Sprintf("[%s:%s,header.rr_type:16]", string(ptype), pname)
	p, err = parseProperty(pstr)
	assert.NoError(t, err, "Failed to parse properly formed property")
	assert.NotNil(t, p, "Returned nil when parsing a properly formed property")
	assert.Equal(t, p.Type, oam.DNSRecordProperty, "Failed to return the correct property type")
	assert.Equal(t, p.Name, pname, "Failed to parse the provided property name")
	assert.Equal(t, p.Attributes["header.rr_type"].Value, "16", "Expected property attribute to match")

	// test that the regexps are being correctly parsed out
	pname = "#/dns.*/#"
	attre := "#/.*google.*/#"
	pstr = fmt.Sprintf("[%s:%s,data:%s]", string(ptype), pname, attre)
	p, err = parseProperty(pstr)
	assert.NoError(t, err, "Failed to parse properly formed property")
	assert.NotNil(t, p, "Returned nil when parsing a properly formed property")
	assert.Equal(t, p.Type, oam.DNSRecordProperty, "Failed to return the correct property type")
	assert.Equal(t, p.Name, pname, "Failed to parse the provided property key")
	assert.NotNil(t, p.Regexp, "Expected the property regexp to be compiled and set")
	assert.Equal(t, p.Attributes["data"].Value, attre, "Expected property attribute to match")
	assert.NotNil(t, p.Attributes["data"].Regexp, "Expected the attribute regexp to be compiled and set")

	// incorrectly formatted property regexp should result in an error
	p, err = parseProperty("<dnsrecordproperty:#/foo(?!bar)/#>")
	assert.Error(t, err, "Failed to detect a property regexp that shouldn't compile")
	assert.Nil(t, p, "Returned a property when the property regexp shouldn't compile")

	// incorrectly formatted property attribute regexp should result in an error
	p, err = parseProperty("<dnsrecordproperty:*,data:#/foo(?!bar)/#>")
	assert.Error(t, err, "Failed to detect an attribute regexp that shouldn't compile")
	assert.Nil(t, p, "Returned a property when the attribute regexp shouldn't compile")
}
