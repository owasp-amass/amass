// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assoc

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlrepo"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/stretchr/testify/assert"
)

func TestExtract(t *testing.T) {
	now := time.Now()

	// create a new in-memory SQLite database for testing
	db, err := assetdb.New(sqlrepo.SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	// create assets and relations for testing
	fentity, err := db.CreateAsset(oamdns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err, "Failed to create FQDN asset")
	assert.NotNil(t, fentity, "FQDN entity should not be nil")
	sentity, err := db.CreateAsset(oamdns.FQDN{Name: "www.owasp.org"})
	assert.NoError(t, err, "Failed to create subdomain asset")
	assert.NotNil(t, sentity, "Subdomain entity should not be nil")
	edge, err := db.CreateEdge(&dbt.Edge{
		Relation:   oamgen.SimpleRelation{Name: "node"},
		FromEntity: fentity,
		ToEntity:   sentity,
	})
	assert.NoError(t, err, "Failed to create edge")
	assert.NotNil(t, edge, "Edge should not be nil")

	// create a triple to successfully extract associations
	triple, err := ParseTriple("<fqdn:owasp.org> - <*:node> -> <fqdn:www.owasp.org>")
	assert.NoError(t, err, "Failed to parse triple")
	assert.NotNil(t, triple, "Parsed triple should not be nil")
	assert.Equal(t, DirectionOutgoing, triple.Direction, "Triple direction should be outgoing")

	// extract associations from the database using the triple
	results, err := Extract(db, []*Triple{triple})
	assert.NoError(t, err, "Failed to extract associations")
	assert.NotNil(t, results, "Results should not be nil")

	// verify the extracted associations
	assert.NotNil(t, results.Node, "Results first node should not be nil")
	assert.Equal(t, oam.FQDN, results.Node.Type, "Results first node type should be FQDN")
	assert.Equal(t, "owasp.org", results.Node.Asset.Key(), "Results first node key should be 'owasp.org'")
	assert.Equal(t, 1, len(results.Node.Relations), "Results first node should have one relation")
	assert.Equal(t, oam.SimpleRelation, results.Node.Relations[0].Type, "Relation type should be SimpleRelation")
	assert.Equal(t, "node", results.Node.Relations[0].Relation.Label(), "Relation label should be 'node'")
	assert.NotNil(t, results.Node.Relations[0].Node, "Relation node should not be nil")
	assert.Equal(t, oam.FQDN, results.Node.Relations[0].Node.Type, "Relation node type should be FQDN")
	assert.Equal(t, "www.owasp.org", results.Node.Relations[0].Node.Asset.Key(), "Relation node key should be 'www.owasp.org'")
	assert.Equal(t, 0, len(results.Node.Relations[0].Node.Relations), "Relation node should have no relations")

	// create a triple that will fail to extract associations
	triple, err = ParseTriple("<fqdn:owasp.org> - <*> -> <fqdn:netsec.owasp.org>")
	assert.NoError(t, err, "Failed to parse the second triple")
	assert.NotNil(t, triple, "Parsed second triple should not be nil")

	// attempt to extract associations from the database using the second triple
	results, err = Extract(db, []*Triple{triple})
	assert.Error(t, err, "Expected an error when extracting associations with the second triple")
	assert.Nil(t, results, "Results should be nil when an error occurs")

	// create another triple that will fail to extract associations
	triple, err = ParseTriple("<fqdn:owasp.org> - <*:dns_record> -> <*>")
	assert.NoError(t, err, "Failed to parse the third triple")
	assert.NotNil(t, triple, "Parsed third triple should not be nil")

	// attempt to extract associations from the database using the third triple
	results, err = Extract(db, []*Triple{triple})
	assert.Error(t, err, "Expected an error when extracting associations with the third triple")
	assert.Nil(t, results, "Results should be nil when an error occurs")

	// add a new asset and relation to the database
	nentity, err := db.CreateAsset(oamnet.IPAddress{Address: netip.MustParseAddr("192.168.1.2")})
	assert.NoError(t, err, "Failed to create IP address asset")
	assert.NotNil(t, nentity, "IP address entity should not be nil")
	edge, err = db.CreateEdge(&dbt.Edge{
		Relation: oamdns.BasicDNSRelation{
			Name: "dns_record",
			Header: oamdns.RRHeader{
				RRType: 1,
				Class:  1,
				TTL:    3600,
			},
		},
		FromEntity: sentity,
		ToEntity:   nentity,
	})
	assert.NoError(t, err, "Failed to create edge for IP address")
	assert.NotNil(t, edge, "Edge for IP address should not be nil")

	// create a triple to successfully extract associations with the new asset
	tstr := fmt.Sprintf("<fqdn:www.owasp.org,since:%s> - <*:dns_record,header.rr_type:1> -> <ipaddress:#/192.*/#>", now.Format(time.DateOnly))
	triple, err = ParseTriple(tstr)
	assert.NoError(t, err, "Failed to parse the fourth triple")
	assert.NotNil(t, triple, "Parsed fourth triple should not be nil")
	assert.Equal(t, DirectionOutgoing, triple.Direction, "Fourth triple direction should be outgoing")

	// extract associations from the database using the fourth triple
	results, err = Extract(db, []*Triple{triple})
	assert.NoError(t, err, "Failed to extract associations with the fourth triple")
	assert.NotNil(t, results, "Results should not be nil for the fourth triple")
}

func TestFindFirstSubject(t *testing.T) {
	// create a new in-memory SQLite database for testing
	db, err := assetdb.New(sqlrepo.SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ipstr := "192.168.1.2"
	// add a new asset to the database
	nentity, err := db.CreateAsset(oamnet.IPAddress{Address: netip.MustParseAddr(ipstr)})
	assert.NoError(t, err, "Failed to create IP address asset")
	assert.NotNil(t, nentity, "IP address entity should not be nil")

	// attempt to find a nil subject in the database
	entity, err := findFirstSubject(db, nil)
	assert.Error(t, err, "Expected an error when finding a nil subject")
	assert.Nil(t, entity, "Entity should be nil when an error occurs")

	// attempt to find an invalid subject in the database
	entity, err = findFirstSubject(db, &Node{
		Type: oam.IPAddress,
		Key:  "192.168.1.TWO",
	})
	assert.Error(t, err, "Expected an error when finding an invalid subject")
	assert.Nil(t, entity, "Entity should be nil when an error occurs")

	// attempt to find a subject that does not exist
	entity, err = findFirstSubject(db, &Node{
		Type: oam.IPAddress,
		Key:  "192.168.1.1",
	})
	assert.Error(t, err, "Expected an error when finding a non-existent subject")
	assert.Nil(t, entity, "Entity should be nil when an error occurs")

	// attempt to find a valid subject in the database
	entity, err = findFirstSubject(db, &Node{
		Type: oam.IPAddress,
		Key:  ipstr,
	})
	assert.NoError(t, err, "Failed to find a valid subject")
	assert.NotNil(t, entity, "Entity should not be nil for a valid subject")
	assert.Equal(t, ipstr, entity.Asset.Key(), "Entity key should match the subject key")
}

func TestEntityPropsMatch(t *testing.T) {
	now := time.Now()

	// create a new in-memory SQLite database for testing
	db, err := assetdb.New(sqlrepo.SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	// create an asset and property for testing
	fentity, err := db.CreateAsset(oamdns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err, "Failed to create FQDN asset")
	assert.NotNil(t, fentity, "FQDN entity should not be nil")

	// test for success and an empty property list when no properties are specified and none are associated
	props, ok := entityPropsMatch(db, fentity, nil)
	assert.True(t, ok, "Expected entity properties to match when no properties are specified")
	assert.Equal(t, 0, len(props), "Expected no matching properties when none are associated")

	// test for failure when a property is specified that is not associated
	p, err := parseProperty("[sourceproperty:test,confidence:100]")
	assert.NoError(t, err, "Failed to parse property")
	assert.NotNil(t, p, "Parsed property should not be nil")
	props, ok = entityPropsMatch(db, fentity, []*Property{p})
	assert.False(t, ok, "Expected entity properties not to match when a non-associated property is specified")
	assert.Equal(t, 0, len(props), "Expected no matching properties when none are associated")

	pname := "test"
	// add a property to the entity and test for success when that property is specified
	tag, err := db.CreateEntityProperty(fentity, &oamgen.SourceProperty{Source: pname, Confidence: 100})
	assert.NoError(t, err, "Failed to create entity property")
	assert.NotNil(t, tag, "Entity property should not be nil")
	props, ok = entityPropsMatch(db, fentity, []*Property{p})
	assert.True(t, ok, "Expected entity properties to match when the associated property is specified")
	assert.Equal(t, 1, len(props), "Expected one matching property when the associated property is specified")
	assert.Equal(t, pname, props[0].Property.Name(), "Property name should match the associated property name")
	assert.Equal(t, "100", props[0].Property.Value(), "Property confidence should match the associated property confidence")

	// add another property to the entity and test for success when both properties are specified
	pname2 := "test2"
	p2, err := parseProperty("[sourceproperty:test2,confidence:100]")
	assert.NoError(t, err, "Failed to parse second property")
	assert.NotNil(t, p2, "Parsed second property should not be nil")
	tag, err = db.CreateEntityProperty(fentity, &oamgen.SourceProperty{Source: pname2, Confidence: 100})
	assert.NoError(t, err, "Failed to create second entity property")
	assert.NotNil(t, tag, "Second entity property should not be nil")
	props, ok = entityPropsMatch(db, fentity, []*Property{p, p2})
	assert.True(t, ok, "Expected entity properties to match when both associated properties are specified")
	assert.Equal(t, 2, len(props), "Expected two matching properties when both associated properties are specified")

	// test for success when only one property specification is provided
	p3, err := parseProperty("[sourceproperty:#/test.*/#,confidence:100,since:" + now.Format(time.DateOnly) + "]")
	assert.NoError(t, err, "Failed to parse third property")
	assert.NotNil(t, p3, "Parsed third property should not be nil")
	props, ok = entityPropsMatch(db, fentity, []*Property{p3})
	assert.True(t, ok, "Expected entity properties to match when the specification matches both associated properties")
	assert.Equal(t, 2, len(props), "Expected two matching properties when the specification matches both associated properties")
}

func TestEdgePropsMatch(t *testing.T) {
	now := time.Now()

	// create a new in-memory SQLite database for testing
	db, err := assetdb.New(sqlrepo.SQLiteMemory, "")
	assert.NoError(t, err, "Failed to create the in-memory sqlite database")
	assert.NotNil(t, db, "Asset database should not be nil")
	defer func() { _ = db.Close() }()

	ipstr := "192.168.1.1"
	// create an asset and relations for an FQDN that resolves to an IP address
	fentity, err := db.CreateAsset(oamdns.FQDN{Name: "owasp.org"})
	assert.NoError(t, err, "Failed to create FQDN asset")
	assert.NotNil(t, fentity, "FQDN entity should not be nil")
	nentity, err := db.CreateAsset(oamnet.IPAddress{Address: netip.MustParseAddr(ipstr)})
	assert.NoError(t, err, "Failed to create subdomain asset")
	assert.NotNil(t, nentity, "Subdomain entity should not be nil")
	edge1, err := db.CreateEdge(&dbt.Edge{
		Relation: oamdns.BasicDNSRelation{
			Name: "dns_record",
			Header: oamdns.RRHeader{
				RRType: 1,
				Class:  1,
				TTL:    3600,
			},
		},
		FromEntity: fentity,
		ToEntity:   nentity,
	})
	assert.NoError(t, err, "Failed to create edge")
	assert.NotNil(t, edge1, "Edge should not be nil")

	// test for success and an empty property list when no properties are specified and none are associated
	props, ok := edgePropsMatch(db, edge1, nil)
	assert.True(t, ok, "Expected edge properties to match when no properties are specified")
	assert.Equal(t, 0, len(props), "Expected no matching properties when none are associated")

	pname := "test"
	// test for failure when a property is specified that is not associated
	p, err := parseProperty("[sourceproperty:test,confidence:100]")
	assert.NoError(t, err, "Failed to parse property")
	assert.NotNil(t, p, "Parsed property should not be nil")
	props, ok = edgePropsMatch(db, edge1, []*Property{p})
	assert.False(t, ok, "Expected edge properties not to match when a non-associated property is specified")
	assert.Equal(t, 0, len(props), "Expected no matching properties when none are associated")

	// add a property to the edge and test for success when that property is specified
	tag, err := db.CreateEdgeProperty(edge1, &oamgen.SourceProperty{Source: pname, Confidence: 100})
	assert.NoError(t, err, "Failed to create edge property")
	assert.NotNil(t, tag, "Edge property should not be nil")
	props, ok = edgePropsMatch(db, edge1, []*Property{p})
	assert.True(t, ok, "Expected edge properties to match when the associated property is specified")
	assert.Equal(t, 1, len(props), "Expected one matching property when the associated property is specified")
	assert.Equal(t, pname, props[0].Property.Name(), "Property name should match the associated property name")
	assert.Equal(t, "100", props[0].Property.Value(), "Property confidence should match the associated property confidence")

	// add another property to the edge and test for success when both properties are specified
	pname2 := "test2"
	p2, err := parseProperty("[sourceproperty:test2,confidence:100]")
	assert.NoError(t, err, "Failed to parse second property")
	assert.NotNil(t, p2, "Parsed second property should not be nil")
	tag, err = db.CreateEdgeProperty(edge1, &oamgen.SourceProperty{Source: pname2, Confidence: 100})
	assert.NoError(t, err, "Failed to create second edge property")
	assert.NotNil(t, tag, "Second edge property should not be nil")
	props, ok = edgePropsMatch(db, edge1, []*Property{p, p2})
	assert.True(t, ok, "Expected edge properties to match when both associated properties are specified")
	assert.Equal(t, 2, len(props), "Expected two matching properties when both associated properties are specified")

	// test for success when only one property specification is provided
	p3, err := parseProperty("[sourceproperty:#/test.*/#,confidence:100,since:" + now.Format(time.DateOnly) + "]")
	assert.NoError(t, err, "Failed to parse third property")
	assert.NotNil(t, p3, "Parsed third property should not be nil")
	props, ok = edgePropsMatch(db, edge1, []*Property{p3})
	assert.True(t, ok, "Expected edge properties to match when the specification matches both associated properties")
	assert.Equal(t, 2, len(props), "Expected two matching properties when the specification matches both associated properties")
}

func TestSubjectToAsset(t *testing.T) {
	tests := []struct {
		Subject       *Node
		ExpectSucceed bool
	}{
		{
			Subject: &Node{
				Type: oam.Account,
				Key:  "112233445566778899",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.AutnumRecord,
				Key:  "AS12345",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.AutonomousSystem,
				Key:  "12345",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.AutonomousSystem,
				Key:  "not-numeric",
			},
			ExpectSucceed: false,
		},
		{
			Subject: &Node{
				Type: oam.ContactRecord,
				Key:  "http://example.com/contact",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.DomainRecord,
				Key:  "example.com",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.File,
				Key:  "file.txt",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.FQDN,
				Key:  "www.example.com",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.FundsTransfer,
				Key:  "txid1234567890abcdef",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.Identifier,
				Key:  "id123456",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.IPAddress,
				Key:  "192.168.1.1",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.IPAddress,
				Key:  "invalid-ip",
			},
			ExpectSucceed: false,
		},
		{
			Subject: &Node{
				Type: oam.IPNetRecord,
				Key:  "192-168-1-1",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.Location,
				Key:  "New York City, NY, USA",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.Netblock,
				Key:  "192.168.1.0/24",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.Netblock,
				Key:  "invalid-cidr",
			},
			ExpectSucceed: false,
		},
		{
			Subject: &Node{
				Type: oam.Organization,
				Key:  "Example Org",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.Person,
				Key:  "John Doe",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.Phone,
				Key:  "+1234567890",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.Product,
				Key:  "Example Product",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.ProductRelease,
				Key:  "v1.0.0",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.Service,
				Key:  "Example Service",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.TLSCertificate,
				Key:  "abcdef1234567890",
			},
			ExpectSucceed: true,
		},
		{
			Subject: &Node{
				Type: oam.URL,
				Key:  "http://example.com",
			},
			ExpectSucceed: true,
		},
	}

	for _, test := range tests {
		asset, err := subjectToAsset(test.Subject)
		if test.ExpectSucceed {
			assert.NoError(t, err, "Expected no error for subject type %s with key %s", test.Subject.Type, test.Subject.Key)
			assert.NotNil(t, asset, "Expected a valid asset for subject type %s with key %s", test.Subject.Type, test.Subject.Key)
			assert.Equal(t, test.Subject.Key, asset.Key(), "Asset key mismatch for subject type %s", test.Subject.Type)
		} else {
			assert.Error(t, err, "Expected an error for subject type %s with key %s", test.Subject.Type, test.Subject.Key)
			assert.Nil(t, asset, "Expected no asset for subject type %s with key %s", test.Subject.Type, test.Subject.Key)
		}
	}
}
