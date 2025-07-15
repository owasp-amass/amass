// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/db"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/platform"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

func SourceToAssetsWithinTTL(session et.Session, name, atype string, src *et.Source, since time.Time) []*dbt.Entity {
	var entities []*dbt.Entity

	switch atype {
	case string(oam.FQDN):
		roots, err := session.Cache().FindEntitiesByContent(&oamdns.FQDN{Name: name}, since)
		if err != nil || len(roots) != 1 {
			return nil
		}
		root := roots[0]

		entities, _ = db.FindByFQDNScope(session.Cache(), root, since)
	case string(oam.Identifier):
		if parts := strings.Split(name, ":"); len(parts) == 2 {
			id := &general.Identifier{
				UniqueID: name,
				ID:       parts[1],
				Type:     parts[0],
			}

			entities, _ = session.Cache().FindEntitiesByContent(id, since)
		}
	case string(oam.AutnumRecord):
		num, err := strconv.Atoi(name)
		if err != nil {
			return nil
		}

		entities, _ = session.Cache().FindEntitiesByContent(&oamreg.AutnumRecord{Number: num}, since)
	case string(oam.IPNetRecord):
		prefix, err := netip.ParsePrefix(name)
		if err != nil {
			return nil
		}

		entities, _ = session.Cache().FindEntitiesByContent(&oamreg.IPNetRecord{CIDR: prefix}, since)
	case string(oam.Service):
		entities, _ = session.Cache().FindEntitiesByContent(&platform.Service{ID: name}, since)
	}

	var results []*dbt.Entity
	for _, entity := range entities {
		if tags, err := session.Cache().GetEntityTags(entity, since, src.Name); err == nil && len(tags) > 0 {
			for _, tag := range tags {
				if tag.Property.PropertyType() == oam.SourceProperty {
					results = append(results, entity)
				}
			}
		}
	}
	return results
}

func StoreFQDNsWithSource(session et.Session, names []string, src *et.Source, plugin, handler string) []*dbt.Entity {
	var results []*dbt.Entity

	if len(names) == 0 || src == nil {
		return results
	}

	for _, name := range names {
		if a, err := session.Cache().CreateAsset(&oamdns.FQDN{Name: name}); err == nil && a != nil {
			results = append(results, a)
			_, _ = session.Cache().CreateEntityProperty(a, &general.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})
		} else {
			session.Log().Error(err.Error(), slog.Group("plugin", "name", plugin, "handler", handler))
		}
	}

	return results
}

func StoreEmailsWithSource(session et.Session, emails []string, src *et.Source, plugin, handler string) []*dbt.Entity {
	var results []*dbt.Entity

	if len(emails) == 0 || src == nil {
		return results
	}

	for _, e := range emails {
		email := strings.ToLower(e)

		if a, err := session.Cache().CreateAsset(&general.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", general.EmailAddress, email),
			ID:       email,
			Type:     general.EmailAddress,
		}); err == nil && a != nil {
			results = append(results, a)
			_, _ = session.Cache().CreateEntityProperty(a, &general.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})
		} else {
			session.Log().Error(err.Error(), slog.Group("plugin", "name", plugin, "handler", handler))
		}
	}

	return results
}

func MarkAssetMonitored(session et.Session, asset *dbt.Entity, src *et.Source) {
	if asset == nil || src == nil {
		return
	}

	if tags, err := session.Cache().GetEntityTags(asset, time.Time{}, "last_monitored"); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if tag.Property.Value() == src.Name {
				_ = session.Cache().DeleteEntityTag(tag.ID)
			}
		}
	}

	_, _ = session.Cache().CreateEntityProperty(asset, general.SimpleProperty{
		PropertyName:  "last_monitored",
		PropertyValue: src.Name,
	})
}

func AssetMonitoredWithinTTL(session et.Session, asset *dbt.Entity, src *et.Source, since time.Time) bool {
	if asset == nil || src == nil || !since.IsZero() {
		return false
	}

	if tags, err := session.Cache().GetEntityTags(asset, since, "last_monitored"); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if tag.Property.Value() == src.Name {
				return true
			}
		}
	}

	return false
}

func CreateServiceAsset(session et.Session, src *dbt.Entity, rel oam.Relation, serv *platform.Service, cert *oamcert.TLSCertificate) (*dbt.Entity, error) {
	var srvs []*dbt.Entity

	if rport, ok := rel.(*general.PortRelation); ok && src != nil && serv != nil {
		srcs := []*dbt.Entity{src}

		if _, ok := src.Asset.(*oamdns.FQDN); ok {
			// check for IP assresses associated with the FQDN
			if edges, err := session.Cache().OutgoingEdges(src, time.Time{}, "dns_record"); err == nil && len(edges) > 0 {
				for _, edge := range edges {
					if to, err := session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && to != nil {
						if _, ok := to.Asset.(*oamnet.IPAddress); ok {
							srcs = append(srcs, to)
						}
					}
				}
			}
		}

		// go though the hosts that could have previously associated with the service
		for _, s := range srcs {
			if edges, err := session.Cache().OutgoingEdges(s, time.Time{}, "port"); err == nil && len(edges) > 0 {
				for _, edge := range edges {
					if eport, ok := edge.Relation.(*general.PortRelation); ok && eport.PortNumber == rport.PortNumber && strings.EqualFold(eport.Protocol, rport.Protocol) {
						if to, err := session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && to != nil {
							if srv, ok := to.Asset.(*platform.Service); ok && srv.OutputLen == serv.OutputLen {
								srvs = append(srvs, to)
							}
						}
					}
				}
			}
		}
	}

	var match *dbt.Entity
	for _, srv := range srvs {
		var num int

		s := srv.Asset.(*platform.Service)
		for _, key := range []string{"Server", "X-Powered-By"} {
			if server1, ok := serv.Attributes[key]; ok && server1[0] != "" {
				if server2, ok := s.Attributes[key]; ok && server1[0] == server2[0] {
					num++
				} else {
					num--
				}
			}
		}

		if cert != nil {
			if edges, err := session.Cache().OutgoingEdges(srv, time.Time{}, "certificate"); err == nil && len(edges) > 0 {
				var found bool

				for _, edge := range edges {
					if t, err := session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && t != nil {
						if c, ok := t.Asset.(*oamcert.TLSCertificate); ok && c.SerialNumber == cert.SerialNumber {
							found = true
							break
						}
					}
				}

				if found {
					num++
				} else {
					continue
				}
			}
		}

		if num > 0 {
			match = srv
			break
		}
	}

	var result *dbt.Entity
	if match != nil {
		result = match
	} else {
		if a, err := session.Cache().CreateAsset(serv); err == nil && a != nil {
			result = a
		} else {
			return nil, errors.New("failed to create the OAM Service asset")
		}
	}

	_, err := session.Cache().CreateEdge(&dbt.Edge{
		Relation:   rel,
		FromEntity: src,
		ToEntity:   result,
	})
	return result, err
}
