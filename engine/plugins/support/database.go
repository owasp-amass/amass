// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/caffix/queue"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/service"
	"github.com/owasp-amass/open-asset-model/source"
)

var dbQueue queue.Queue

func AppendToDBQueue(callback func()) {
	dbQueue.Append(callback)
}

func processDBCallbacks() {
loop:
	for {
		select {
		case <-done:
			break loop
		case <-dbQueue.Signal():
			dbQueue.Process(func(data interface{}) {
				if callback, ok := data.(func()); ok {
					callback()
				}
			})
		}
	}

	dbQueue.Process(func(data interface{}) {
		if callback, ok := data.(func()); ok {
			callback()
		}
	})
}

func GetSource(session et.Session, psrc *source.Source) *dbt.Asset {
	src, hit := session.Cache().GetAsset(psrc)
	if hit && src != nil {
		return src
	}

	done := make(chan *dbt.Asset, 1)
	AppendToDBQueue(func() {
		if session.Done() {
			done <- nil
			return
		}

		if refs, err := session.DB().FindByContent(psrc, time.Time{}); err == nil {
			for _, ref := range refs {
				if src, ok := ref.Asset.(*source.Source); ok && src != nil && src.Name == psrc.Name {
					if datasrc, err := session.DB().FindById(ref.ID, time.Time{}); err == nil {
						done <- datasrc
						return
					}
				}
			}
		}

		datasrc, err := session.DB().Create(nil, "", psrc)
		if err != nil {
			done <- nil
			return
		}
		done <- datasrc
	})

	src = <-done
	if src != nil {
		session.Cache().SetAsset(src)
	}
	close(done)
	return src
}

func SourceToAssetsWithinTTL(session et.Session, name, atype string, src *dbt.Asset, since time.Time) []*dbt.Asset {
	var results []*dbt.Asset

	done := make(chan struct{}, 1)
	AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if session.Done() {
			return
		}

		if !since.IsZero() {
			return
		}

		oursrc, ok := src.Asset.(*source.Source)
		if !ok || oursrc == nil {
			return
		}

		from := "((assets as srcs inner join relations on srcs.id = relations.to_asset_id) "
		from2 := "inner join assets on relations.from_asset_id = assets.id) "
		where := "where srcs.type = 'Source' and assets.type = '" + atype + "' and relations.type = 'source' "
		where2 := "and relations.last_seen > '" + since.Format("2006-01-02 15:04:05") + "'"
		where3 := " and srcs.content->>'name' = '" + oursrc.Name + "'"

		var like string
		switch atype {
		case string(oam.FQDN):
			like = " and assets.content->>'name' like '%" + name + "'"
		case string(oam.EmailAddress):
			like = " and assets.content->>'address' = '" + name + "'"
		case string(oam.AutnumRecord):
			like = " and assets.content->>'number' = " + name
		case string(oam.IPNetRecord):
			like = " and assets.content->>'cidr' = '" + name + "'"
		case string(oam.NetworkEndpoint):
			like = " and assets.content->>'address' = '" + name + "'"
		case string(oam.Service):
			like = " and assets.content->>'identifier' = '" + name + "'"
		}

		query := from + from2 + where + where2 + where3 + like
		if assets, err := session.DB().AssetQuery(query); err == nil && len(assets) > 0 {
			results = append(results, assets...)
		}
	})
	<-done
	close(done)
	return results
}

func StoreFQDNsWithSource(session et.Session, names []string, src *dbt.Asset, plugin, handler string) []*dbt.Asset {
	var assets []*dbt.Asset

	if len(names) == 0 || src == nil {
		return assets
	}

	done := make(chan struct{}, 1)
	AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if session.Done() {
			return
		}

		for _, name := range names {
			if a, err := session.DB().Create(nil, "", &domain.FQDN{Name: name}); err == nil {
				if a != nil {
					assets = append(assets, a)
					_, _ = session.DB().Link(a, "source", src)
				}
			} else {
				session.Log().Error(err.Error(), slog.Group("plugin", "name", plugin, "handler", handler))
			}
		}
	})
	<-done
	close(done)
	return assets
}

func StoreEmailsWithSource(session et.Session, emails []string, src *dbt.Asset, plugin, handler string) []*dbt.Asset {
	var assets []*dbt.Asset

	if len(emails) == 0 || src == nil {
		return assets
	}

	done := make(chan struct{}, 1)
	AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if session.Done() {
			return
		}

		for _, email := range emails {
			e := EmailToOAMEmailAddress(email)
			if e == nil {
				continue
			}
			if a, err := session.DB().Create(nil, "", e); err == nil {
				if a != nil {
					assets = append(assets, a)
					_, _ = session.DB().Link(a, "source", src)
				}
			} else {
				session.Log().Error(err.Error(), slog.Group("plugin", "name", plugin, "handler", handler))
			}
		}
	})
	<-done
	close(done)
	return assets
}

func MarkAssetMonitored(session et.Session, asset, src *dbt.Asset) {
	if asset == nil || src == nil {
		return
	}

	done := make(chan *dbt.Relation, 1)
	AppendToDBQueue(func() {
		if session.Done() {
			done <- nil
			return
		}

		rel, _ := session.DB().Link(asset, "monitored_by", src)
		done <- rel
	})
	rel := <-done
	close(done)

	if rel == nil {
		return
	}

	if a, hit := session.Cache().GetAsset(asset.Asset); hit && a != nil {
		if s, hit := session.Cache().GetAsset(src.Asset); hit && s != nil {
			session.Cache().SetRelation(rel)
		}
	}
}

func AssetMonitoredWithinTTL(session et.Session, asset, src *dbt.Asset, since time.Time) bool {
	if asset == nil || src == nil || !since.IsZero() {
		return false
	}

	oursrc, ok := src.Asset.(*source.Source)
	if !ok || oursrc == nil {
		return false
	}

	now := time.Now()
	a, hit := session.Cache().GetAsset(asset.Asset)
	if hit && a != nil {
		if _, found := session.Cache().GetRelations(&dbt.Relation{
			Type:      "monitored_by",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: a,
			ToAsset:   src,
		}); found {
			return true
		}
	}

	done := make(chan bool, 1)
	AppendToDBQueue(func() {
		if session.Done() {
			done <- false
			return
		}

		from := "((assets inner join relations on assets.id = relations.from_asset_id) "
		from2 := "inner join assets as srcs on relations.to_asset_id = srcs.id) "
		where := "where srcs.type = 'Source' and assets.id = " + asset.ID + " and relations.type = 'monitored_by' "
		where2 := "and relations.last_seen > '" + since.Format("2006-01-02 15:04:05") + "'"
		where3 := " and srcs.content->>'name' = '" + oursrc.Name + "'"

		var monitored bool
		query := from + from2 + where + where2 + where3
		if assets, err := session.DB().AssetQuery(query); err == nil && len(assets) > 0 {
			monitored = true
		}
		done <- monitored
	})

	monitored := <-done
	close(done)

	if monitored {
		now = time.Now()
		session.Cache().SetRelation(&dbt.Relation{
			Type:      "monitored_by",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: a,
			ToAsset:   src,
		})
	}
	return monitored
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
