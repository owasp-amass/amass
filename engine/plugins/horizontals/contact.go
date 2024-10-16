// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"errors"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	"github.com/owasp-amass/amass/v4/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
)

type horContact struct {
	name   string
	plugin *horizPlugin
}

func (h *horContact) Name() string {
	return h.name
}

func (h *horContact) check(e *et.Event) error {
	_, ok := e.Asset.Asset.(*contact.ContactRecord)
	if !ok {
		return errors.New("failed to extract the ContactRecord asset")
	}

	matches, err := e.Session.Config().CheckTransformations(
		string(oam.ContactRecord), string(oam.ContactRecord), h.plugin.name)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	src := support.GetSource(e.Session, h.plugin.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	conf := matches.Confidence(h.plugin.name)
	if conf == -1 {
		conf = matches.Confidence(string(oam.ContactRecord))
	}

	if assocs := h.lookup(e, e.Asset, conf); len(assocs) > 0 {
		var impacted []*dbt.Asset
		for _, assoc := range assocs {
			if assoc.ScopeChange {
				h.plugin.log.Info(assoc.Rationale)
				impacted = append(impacted, assoc.ImpactedAssets...)
			}
		}

		var assets []*dbt.Asset
		for _, im := range impacted {
			if a, hit := e.Session.Cache().GetAsset(im.Asset); hit && a != nil {
				assets = append(assets, a)
			} else if n := h.store(e, im.Asset, src); n != nil {
				assets = append(assets, n)
			}
		}

		if len(assets) > 0 {
			h.plugin.process(e, assets, src)
		}
	}
	return nil
}

func (h *horContact) lookup(e *et.Event, asset *dbt.Asset, conf int) []*scope.Association {
	rtypes := []string{"organization", "location", "email"}

	var results []*scope.Association
	for _, rtype := range rtypes {
		if relations, hit := e.Session.Cache().GetRelations(&dbt.Relation{
			Type:      rtype,
			FromAsset: asset,
		}); hit && len(relations) > 0 {
			for _, relation := range relations {
				// check if this asset discoveries could change the scope
				if assocs, err := e.Session.Scope().IsAssociated(e.Session.Cache(), &scope.Association{
					Submission:  relation.ToAsset,
					Confidence:  conf,
					ScopeChange: true,
				}); err == nil && len(assocs) > 0 {
					results = append(results, assocs...)
				}
			}
		}
	}
	return results
}

func (h *horContact) store(e *et.Event, asset oam.Asset, src *dbt.Asset) *dbt.Asset {
	done := make(chan *dbt.Asset, 1)
	defer close(done)

	support.AppendToDBQueue(func() {
		if e.Session.Done() {
			done <- nil
			return
		}

		a, err := e.Session.DB().Create(nil, "", asset)
		if err != nil || a == nil {
			done <- nil
			return
		}

		_, _ = e.Session.DB().Link(a, "source", src)
		done <- a
	})

	return <-done
}
