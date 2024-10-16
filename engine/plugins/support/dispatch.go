// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"log/slog"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	et "github.com/owasp-amass/engine/types"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
)

type Finding struct {
	From     *dbt.Asset
	FromName string
	To       *dbt.Asset
	ToName   string
	ToMeta   interface{}
	Rel      string
}

func ProcessAssetsWithSource(e *et.Event, findings []*Finding, src *dbt.Asset, pname, hname string) {
	now := time.Now()

	for _, finding := range findings {
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    finding.ToName,
			Meta:    finding.ToMeta,
			Asset:   finding.To,
			Session: e.Session,
		})

		if to, hit := e.Session.Cache().GetAsset(finding.To.Asset); hit && to != nil {
			if from, hit := e.Session.Cache().GetAsset(finding.From.Asset); hit && from != nil {
				e.Session.Cache().SetRelation(&dbt.Relation{
					Type:      finding.Rel,
					CreatedAt: now,
					LastSeen:  now,
					FromAsset: finding.From,
					ToAsset:   finding.To,
				})
				e.Session.Cache().SetRelation(&dbt.Relation{
					Type:      "source",
					CreatedAt: now,
					LastSeen:  now,
					FromAsset: finding.To,
					ToAsset:   src,
				})
				e.Session.Log().Info("relationship discovered", "from", finding.FromName, "relation",
					finding.Rel, "to", finding.ToName, slog.Group("plugin", "name", pname, "handler", hname))
			}
		}
	}
}

func ProcessFQDNsWithSource(e *et.Event, assets []*dbt.Asset, src *dbt.Asset) {
	now := time.Now()

	for _, a := range assets {
		fqdn, ok := a.Asset.(*domain.FQDN)
		if !ok || fqdn == nil {
			continue
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    fqdn.Name,
			Asset:   a,
			Session: e.Session,
		})

		if finding, hit := e.Session.Cache().GetAsset(a.Asset); hit && finding != nil {
			e.Session.Cache().SetRelation(&dbt.Relation{
				Type:      "source",
				CreatedAt: now,
				LastSeen:  now,
				FromAsset: finding,
				ToAsset:   src,
			})
		}
	}
}

func ProcessEmailsWithSource(e *et.Event, assets []*dbt.Asset, src *dbt.Asset) {
	now := time.Now()

	for _, a := range assets {
		email, ok := a.Asset.(*contact.EmailAddress)
		if !ok || email == nil {
			continue
		}

		if _, conf := e.Session.Scope().IsAssetInScope(email, 0); conf == 0 {
			continue
		}

		meta := e.Meta
		if meta == nil {
			meta = &et.EmailMeta{
				VerifyAttempted: false,
				Verified:        false,
			}
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    email.Address,
			Meta:    meta,
			Asset:   a,
			Session: e.Session,
		})

		if finding, hit := e.Session.Cache().GetAsset(a.Asset); hit && finding != nil {
			e.Session.Cache().SetRelation(&dbt.Relation{
				Type:      "source",
				CreatedAt: now,
				LastSeen:  now,
				FromAsset: finding,
				ToAsset:   src,
			})
		}
	}
}
