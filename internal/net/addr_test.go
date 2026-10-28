// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/network"
)

type addrTestRepository struct {
	repository.Repository
	fqdn   *dbt.Entity
	edges  []*dbt.Edge
	assets map[string]*dbt.Entity
}

func (r *addrTestRepository) FindEntitiesByContent(_ context.Context, _ oam.AssetType, _ time.Time, _ int, filters dbt.ContentFilters) ([]*dbt.Entity, error) {
	if filters["name"] == r.fqdn.Asset.(*oamdns.FQDN).Name {
		return []*dbt.Entity{r.fqdn}, nil
	}
	return nil, nil
}

func (r *addrTestRepository) OutgoingEdges(_ context.Context, entity *dbt.Entity, _ time.Time, _ ...string) ([]*dbt.Edge, error) {
	var edges []*dbt.Edge
	for _, edge := range r.edges {
		if edge.FromEntity != nil && edge.FromEntity.ID == entity.ID {
			edges = append(edges, edge)
		}
	}
	return edges, nil
}

func (r *addrTestRepository) FindEntityById(_ context.Context, id string) (*dbt.Entity, error) {
	if entity, ok := r.assets[id]; ok {
		return entity, nil
	}
	if r.fqdn.ID == id {
		return r.fqdn, nil
	}
	return nil, errors.New("entity not found")
}

func TestNamesToAddrsPrefersDirectAddressRegardlessOfEdgeOrder(t *testing.T) {
	name := &oamdns.FQDN{Name: "example.test"}
	fqdn := &dbt.Entity{ID: "name", Asset: name}
	directIP := &network.IPAddress{Address: netip.MustParseAddr("192.0.2.10")}
	indirectIP := &network.IPAddress{Address: netip.MustParseAddr("198.51.100.20")}
	directEntity := &dbt.Entity{ID: "direct-ip", Asset: directIP}
	indirectEntity := &dbt.Entity{ID: "indirect-ip", Asset: indirectIP}
	target := &dbt.Entity{ID: "mx-target", Asset: &oamdns.FQDN{Name: "mx.example.test"}}
	directEdge := &dbt.Edge{FromEntity: fqdn, ToEntity: directEntity, Relation: &oamdns.BasicDNSRelation{Header: oamdns.RRHeader{RRType: 1}}}
	mxEdge := &dbt.Edge{FromEntity: fqdn, ToEntity: target, Relation: &oamdns.PrefDNSRelation{Header: oamdns.RRHeader{RRType: 15}}}
	targetIP := &dbt.Edge{FromEntity: target, ToEntity: indirectEntity, Relation: &oamdns.BasicDNSRelation{Header: oamdns.RRHeader{RRType: 28}}}
	db := &addrTestRepository{fqdn: fqdn, edges: []*dbt.Edge{mxEdge, directEdge, targetIP}, assets: map[string]*dbt.Entity{
		directEntity.ID: directEntity, indirectEntity.ID: indirectEntity, target.ID: target,
	}}
	pairs, err := NamesToAddrs(context.Background(), db, time.Time{}, name.Name)
	if err != nil {
		t.Fatalf("NamesToAddrs returned error: %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("expected one result for direct address, got %d", len(pairs))
	}
	if got := pairs[0].Addr.Address.String(); got != "192.0.2.10" {
		t.Fatalf("expected direct address 192.0.2.10 to take precedence, got %s", got)
	}
}

func TestNamesToAddrsReturnsBothDirectAAndAAAA(t *testing.T) {
	name := &oamdns.FQDN{Name: "example.test"}
	fqdn := &dbt.Entity{ID: "name", Asset: name}
	ipv4 := &dbt.Entity{ID: "v4", Asset: &network.IPAddress{Address: netip.MustParseAddr("192.0.2.10")}}
	ipv6 := &dbt.Entity{ID: "v6", Asset: &network.IPAddress{Address: netip.MustParseAddr("2001:db8::10")}}
	edges := []*dbt.Edge{
		{FromEntity: fqdn, ToEntity: ipv4, Relation: &oamdns.BasicDNSRelation{Header: oamdns.RRHeader{RRType: 1}}},
		{FromEntity: fqdn, ToEntity: ipv6, Relation: &oamdns.BasicDNSRelation{Header: oamdns.RRHeader{RRType: 28}}},
	}
	db := &addrTestRepository{fqdn: fqdn, edges: edges, assets: map[string]*dbt.Entity{ipv4.ID: ipv4, ipv6.ID: ipv6}}
	pairs, err := NamesToAddrs(context.Background(), db, time.Time{}, name.Name)
	if err != nil {
		t.Fatalf("NamesToAddrs returned error: %v", err)
	}
	if len(pairs) != 2 {
		t.Fatalf("expected both A and AAAA results, got %d", len(pairs))
	}
}

func TestNamesToAddrsPrefersCNAMEOverInfrastructure(t *testing.T) {
	name := &oamdns.FQDN{Name: "example.test"}
	fqdn := &dbt.Entity{ID: "name", Asset: name}
	alias := &dbt.Entity{ID: "alias", Asset: &oamdns.FQDN{Name: "alias.example.test"}}
	mxTarget := &dbt.Entity{ID: "mx-target", Asset: &oamdns.FQDN{Name: "mx.example.test"}}
	aliasIP := &dbt.Entity{ID: "alias-ip", Asset: &network.IPAddress{Address: netip.MustParseAddr("192.0.2.30")}}
	mxIP := &dbt.Entity{ID: "mx-ip", Asset: &network.IPAddress{Address: netip.MustParseAddr("198.51.100.40")}}
	edges := []*dbt.Edge{
		{FromEntity: fqdn, ToEntity: mxTarget, Relation: &oamdns.PrefDNSRelation{Header: oamdns.RRHeader{RRType: 15}}},
		{FromEntity: fqdn, ToEntity: alias, Relation: &oamdns.BasicDNSRelation{Header: oamdns.RRHeader{RRType: 5}}},
		{FromEntity: alias, ToEntity: aliasIP, Relation: &oamdns.BasicDNSRelation{Header: oamdns.RRHeader{RRType: 1}}},
		{FromEntity: mxTarget, ToEntity: mxIP, Relation: &oamdns.BasicDNSRelation{Header: oamdns.RRHeader{RRType: 1}}},
	}
	db := &addrTestRepository{fqdn: fqdn, edges: edges, assets: map[string]*dbt.Entity{
		alias.ID: alias, mxTarget.ID: mxTarget, aliasIP.ID: aliasIP, mxIP.ID: mxIP,
	}}
	pairs, err := NamesToAddrs(context.Background(), db, time.Time{}, name.Name)
	if err != nil {
		t.Fatalf("NamesToAddrs returned error: %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("expected one CNAME result, got %d", len(pairs))
	}
	if got := pairs[0].Addr.Address.String(); got != "192.0.2.30" {
		t.Fatalf("expected CNAME address 192.0.2.30 to take precedence, got %s", got)
	}
}
