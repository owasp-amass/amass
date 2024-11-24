// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"errors"
	"log/slog"
	"net/netip"
	"strconv"
	"time"

	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/property"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/service"
)

func SourceToAssetsWithinTTL(session et.Session, name, atype string, src *et.Source, since time.Time) []*dbt.Entity {
	var result []*dbt.Entity

	switch atype {
	case string(oam.FQDN):
		roots, err := session.Cache().FindEntityByContent(&domain.FQDN{Name: name}, since)
		if err != nil || len(roots) != 1 {
			return nil
		}
		root := roots[0]

		if entities, err := utils.FindByFQDNScope(session.Cache(), root, since); err == nil {
			for _, entity := range entities {
				if tags, err := session.Cache().GetEntityTags(entity, since, src.Name); err == nil && len(tags) > 0 {
					for _, tag := range tags {
						if tag.Property.PropertyType() == oam.SourceProperty {
							result = append(result, entity)
						}
					}
				}
			}
		}
	case string(oam.EmailAddress):
		if ents, err := session.Cache().FindEntityByContent(EmailToOAMEmailAddress(name), since); err == nil && len(ents) == 1 {
			entity := ents[0]

			if tags, err := session.Cache().GetEntityTags(entity, since, src.Name); err == nil && len(tags) > 0 {
				for _, tag := range tags {
					if tag.Property.PropertyType() == oam.SourceProperty {
						result = append(result, entity)
					}
				}
			}
		}
	case string(oam.AutnumRecord):
		num, err := strconv.Atoi(name)
		if err != nil {
			return nil
		}

		if ents, err := session.Cache().FindEntityByContent(&oamreg.AutnumRecord{Number: num}, since); err == nil && len(ents) == 1 {
			entity := ents[0]

			if tags, err := session.Cache().GetEntityTags(entity, since, src.Name); err == nil && len(tags) > 0 {
				for _, tag := range tags {
					if tag.Property.PropertyType() == oam.SourceProperty {
						result = append(result, entity)
					}
				}
			}
		}
	case string(oam.IPNetRecord):
		prefix, err := netip.ParsePrefix(name)
		if err != nil {
			return nil
		}

		if ents, err := session.Cache().FindEntityByContent(&oamreg.IPNetRecord{CIDR: prefix}, since); err == nil && len(ents) == 1 {
			entity := ents[0]

			if tags, err := session.Cache().GetEntityTags(entity, since, src.Name); err == nil && len(tags) > 0 {
				for _, tag := range tags {
					if tag.Property.PropertyType() == oam.SourceProperty {
						result = append(result, entity)
					}
				}
			}
		}
	case string(oam.Service):
		if ents, err := session.Cache().FindEntityByContent(&service.Service{Identifier: name}, since); err == nil && len(ents) == 1 {
			entity := ents[0]

			if tags, err := session.Cache().GetEntityTags(entity, since, src.Name); err == nil && len(tags) > 0 {
				for _, tag := range tags {
					if tag.Property.PropertyType() == oam.SourceProperty {
						result = append(result, entity)
					}
				}
			}
		}
	}

	return result
}

func StoreFQDNsWithSource(session et.Session, names []string, src *et.Source, plugin, handler string) []*dbt.Entity {
	var results []*dbt.Entity

	if len(names) == 0 || src == nil {
		return results
	}

	for _, name := range names {
		if a, err := session.Cache().CreateAsset(&domain.FQDN{Name: name}); err == nil && a != nil {
			results = append(results, a)
			_, _ = session.Cache().CreateEntityProperty(a, &property.SourceProperty{
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

	for _, email := range emails {
		e := EmailToOAMEmailAddress(email)
		if e == nil {
			continue
		}
		if a, err := session.Cache().CreateAsset(e); err == nil && a != nil {
			results = append(results, a)
			_, _ = session.Cache().CreateEntityProperty(a, &property.SourceProperty{
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

	_, _ = session.Cache().CreateEntityProperty(asset, property.SimpleProperty{
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

func CreateServiceAsset(session et.Session, src *dbt.Asset, relation string, serv *service.Service, cert *oamcert.TLSCertificate) (*dbt.Asset, error) {
	var result *dbt.Asset

	done := make(chan struct{}, 1)
	AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if session.Done() {
			return
		}

		where := "assets where assets.type = 'Service' "
		where2 := "and assets.content->>'banner_length' = '" + strconv.Itoa(serv.BannerLen) + "'"
		assets, _ := session.DB().AssetQuery(where + where2)

		var match *dbt.Asset
		for _, a := range assets {
			var num int

			s := a.Asset.(*service.Service)
			for _, key := range []string{"Server", "X-Powered-By"} {
				if server1, ok := serv.Headers[key]; ok && server1[0] != "" {
					if server2, ok := s.Headers[key]; ok && server1[0] == server2[0] {
						num++
					} else {
						num--
					}
				}
			}

			if cert != nil {
				if rels, err := session.DB().OutgoingRelations(a, time.Time{}, "certificate"); err == nil && len(rels) > 0 {
					var found bool

					for _, rel := range rels {
						if t, err := session.DB().FindById(rel.ToAsset.ID, time.Time{}); err == nil && t != nil {
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
				match = a
				break
			}
		}

		if match != nil {
			result = match
			_, _ = session.DB().Link(src, relation, match)
		} else {
			if a, err := session.DB().Create(src, relation, serv); err == nil && a != nil {
				result = a
			}
		}

	})
	<-done
	close(done)

	var err error
	if result == nil {
		err = errors.New("failed to create the OAM Service asset")
	}
	return result, err
}
