// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/platform"
)

func StoreFQDNsWithSource(session et.Session, names []string, src *et.Source, plugin, handler string) []*dbt.Entity {
	var results []*dbt.Entity

	if len(names) == 0 || src == nil {
		return results
	}

	ctx, cancel := context.WithTimeout(session.Ctx(), 30*time.Second)
	defer cancel()

	for _, name := range names {
		if a, err := session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: name}); err == nil && a != nil {
			results = append(results, a)
			_, _ = session.DB().CreateEntityProperty(ctx, a, &general.SourceProperty{
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

	ctx, cancel := context.WithTimeout(session.Ctx(), 30*time.Second)
	defer cancel()

	for _, e := range emails {
		email := strings.ToLower(e)

		if a, err := session.DB().CreateAsset(ctx, &general.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", general.EmailAddress, email),
			ID:       email,
			Type:     general.EmailAddress,
		}); err == nil && a != nil {
			results = append(results, a)
			_, _ = session.DB().CreateEntityProperty(ctx, a, &general.SourceProperty{
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

	ctx, cancel := context.WithTimeout(session.Ctx(), 3*time.Second)
	defer cancel()

	_, _ = session.DB().CreateEntityProperty(ctx, asset, general.SimpleProperty{
		PropertyName:  "last_monitored",
		PropertyValue: src.Name,
	})
}

func AssetMonitoredWithinTTL(session et.Session, asset *dbt.Entity, src *et.Source, since time.Time) bool {
	if asset == nil || src == nil || since.IsZero() {
		return false
	}

	ctx, cancel := context.WithTimeout(session.Ctx(), 3*time.Second)
	defer cancel()

	if tags, err := session.DB().FindEntityTags(ctx, asset, since, "last_monitored"); err == nil && len(tags) > 0 {
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

	ctx, cancel := context.WithTimeout(session.Ctx(), 30*time.Second)
	defer cancel()

	if rport, ok := rel.(*general.PortRelation); ok && src != nil && serv != nil {
		srcs := []*dbt.Entity{src}

		if _, ok := src.Asset.(*oamdns.FQDN); ok {
			// check for IP assresses associated with the FQDN
			if edges, err := session.DB().OutgoingEdges(ctx, src, time.Time{}, "dns_record"); err == nil && len(edges) > 0 {
				for _, edge := range edges {
					if to, err := session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && to != nil {
						if _, ok := to.Asset.(*oamnet.IPAddress); ok {
							srcs = append(srcs, to)
						}
					}
				}
			}
		}

		// go though the hosts that could have previously associated with the service
		for _, s := range srcs {
			if edges, err := session.DB().OutgoingEdges(ctx, s, time.Time{}); err == nil && len(edges) > 0 {
				for _, edge := range edges {
					if eport, ok := edge.Relation.(*general.PortRelation); ok &&
						eport.PortNumber == rport.PortNumber && strings.EqualFold(eport.Protocol, rport.Protocol) {
						if to, err := session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && to != nil {
							if srv, ok := to.Asset.(*platform.Service); ok && srv.OutputLen != 0 && srv.OutputLen == serv.OutputLen {
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

		s, valid := srv.Asset.(*platform.Service)
		if !valid {
			continue
		}

		// compare some of the service attributes to find a match
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
			if edges, err := session.DB().OutgoingEdges(ctx, srv, time.Time{}, "certificate"); err == nil && len(edges) > 0 {
				var found bool

				for _, edge := range edges {
					if t, err := session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && t != nil {
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

	if match == nil {
		if a, err := session.DB().CreateAsset(ctx, serv); err == nil && a != nil {
			match = a
		} else {
			return nil, errors.New("failed to create the OAM Service asset")
		}
	}

	_, err := session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   rel,
		FromEntity: src,
		ToEntity:   match,
	})
	return match, err
}
