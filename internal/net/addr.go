// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"errors"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/network"
)

func ReadASPrefixes(ctx context.Context, db repository.Repository, asn int, since time.Time) []string {
	var prefixes []string

	ents, err := db.FindEntitiesByContent(ctx, oam.AutonomousSystem, since, 1, dbt.ContentFilters{
		"number": asn,
	})
	if err != nil || len(ents) == 0 {
		return prefixes
	}

	fqdn := ents[0]
	if edges, err := db.OutgoingEdges(ctx, fqdn, since, "announces"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := db.FindEntityById(ctx, edge.ToEntity.ID); err != nil {
				continue
			} else if netblock, ok := a.Asset.(*network.Netblock); ok {
				prefixes = append(prefixes, netblock.CIDR.String())
			}
		}
	}

	return prefixes
}

type NameAddrPair struct {
	FQDN *oamdns.FQDN
	Addr *network.IPAddress
}

func NamesToAddrs(ctx context.Context, db repository.Repository, since time.Time, names ...string) ([]*NameAddrPair, error) {
	var fqdns []*dbt.Entity

	for _, name := range names {
		if ents, err := db.FindEntitiesByContent(ctx, oam.FQDN, since, 1, dbt.ContentFilters{
			"name": name,
		}); err == nil && len(ents) == 1 {
			fqdns = append(fqdns, ents[0])
		}
	}

	var results []*NameAddrPair
	for _, fqdn := range fqdns {
		edges, err := db.OutgoingEdges(ctx, fqdn, since, "dns_record")
		if err != nil || len(edges) == 0 {
			continue
		}

		name, ok := fqdn.Asset.(*oamdns.FQDN)
		if !ok {
			continue
		}

		// Prefer addresses attached directly to this name, independent of edge order.
		if appendDirectAddrs(ctx, db, fqdn, edges, since, &results) {
			continue
		}

		// A CNAME is the next-best match; avoid falling back to unrelated infrastructure
		// records when the alias chain has a resolvable address.
		if appendCNAMEAddrs(ctx, db, fqdn, edges, since, &results) {
			continue
		}

		// Preserve legacy MX/NS/SRV fallback only when the name and its aliases have no IP.
		for _, edge := range edges {
			switch v := edge.Relation.(type) {
			case *oamdns.PrefDNSRelation:
				if v.Header.RRType != 2 && v.Header.RRType != 15 {
					continue
				}
			case *oamdns.SRVDNSRelation:
				if v.Header.RRType != 33 {
					continue
				}
			default:
				continue
			}

			if ip, err := oneMoreName(ctx, db, edge.ToEntity, since); err == nil {
				results = append(results, &NameAddrPair{FQDN: name, Addr: ip})
				break
			}
		}
	}

	return results, nil
}

func getAddr(ctx context.Context, db repository.Repository, ip *dbt.Entity, since time.Time) (*network.IPAddress, error) {
	if entity, err := db.FindEntityById(ctx, ip.ID); err == nil && entity != nil {
		if ip, ok := entity.Asset.(*network.IPAddress); ok {
			return ip, nil
		}
	}
	return nil, errors.New("failed to extract the IP address")
}

func oneMoreName(ctx context.Context, db repository.Repository, fqdn *dbt.Entity, since time.Time) (*network.IPAddress, error) {
	if edges, err := db.OutgoingEdges(ctx, fqdn, since, "dns_record"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if rel, ok := edge.Relation.(*oamdns.BasicDNSRelation); ok && (rel.Header.RRType == 1 || rel.Header.RRType == 28) {
				return getAddr(ctx, db, edge.ToEntity, since)
			}
		}
	}
	return nil, errors.New("failed to traverse the FQDN")
}

func cnameQuery(ctx context.Context, db repository.Repository, fqdn *dbt.Entity, since time.Time) (*network.IPAddress, error) {
	set := stringset.New()
	defer set.Close()

	next := fqdn
loop:
	for i := 0; i < 10; i++ {
		n, err := db.FindEntityById(ctx, next.ID)
		if err != nil || set.Has(n.Asset.Key()) {
			break
		}
		set.Insert(n.Asset.Key())

		if edges, err := db.OutgoingEdges(ctx, n, since, "dns_record"); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if rel, ok := edge.Relation.(*oamdns.BasicDNSRelation); ok {
					if rel.Header.RRType == 1 || rel.Header.RRType == 28 {
						return getAddr(ctx, db, edge.ToEntity, since)
					} else if rel.Header.RRType == 5 {
						next = edge.ToEntity
						continue loop
					}
				}
			}
		}
	}

	return nil, errors.New("failed to traverse the aliases")
}

func appendDirectAddrs(ctx context.Context, db repository.Repository, fqdn *dbt.Entity, edges []*dbt.Edge, since time.Time, results *[]*NameAddrPair) bool {
	found := false
	name, ok := fqdn.Asset.(*oamdns.FQDN)
	if !ok {
		return false
	}
	for _, edge := range edges {
		rel, ok := edge.Relation.(*oamdns.BasicDNSRelation)
		if !ok || (rel.Header.RRType != 1 && rel.Header.RRType != 28) {
			continue
		}
		if ip, err := getAddr(ctx, db, edge.ToEntity, since); err == nil {
			*results = append(*results, &NameAddrPair{FQDN: name, Addr: ip})
			found = true
		}
	}
	return found
}

func appendCNAMEAddrs(ctx context.Context, db repository.Repository, fqdn *dbt.Entity, edges []*dbt.Edge, since time.Time, results *[]*NameAddrPair) bool {
	found := false
	name, ok := fqdn.Asset.(*oamdns.FQDN)
	if !ok {
		return false
	}
	for _, edge := range edges {
		rel, ok := edge.Relation.(*oamdns.BasicDNSRelation)
		if !ok || rel.Header.RRType != 5 {
			continue
		}
		if ip, err := cnameQuery(ctx, db, edge.ToEntity, since); err == nil {
			*results = append(*results, &NameAddrPair{FQDN: name, Addr: ip})
			found = true
		}
	}
	return found
}
