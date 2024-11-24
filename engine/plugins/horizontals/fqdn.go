// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"errors"
	"fmt"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	"github.com/owasp-amass/amass/v4/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/property"
	"golang.org/x/net/publicsuffix"
)

type horfqdn struct {
	name   string
	plugin *horizPlugin
}

func (h *horfqdn) Name() string {
	return h.name
}

func (h *horfqdn) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	rels, hit := e.Session.Cache().GetOutgoingRelations(e.Asset, "ptr_record")
	if !hit && !support.NameResolved(e.Session, fqdn) {
		return nil
	}
	if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf > 0 {
		return nil
	}

	matches, err := e.Session.Config().CheckTransformations(string(oam.FQDN), string(oam.FQDN), h.plugin.name)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	conf := matches.Confidence(h.plugin.name)
	if conf == -1 {
		conf = matches.Confidence(string(oam.FQDN))
	}

	src := h.plugin.Source
	if hit && len(rels) > 0 {
		h.checkPTR(e, rels, e.Asset, src)
		return nil
	}

	if assocs := h.lookup(e, e.Asset, conf); len(assocs) > 0 {
		var impacted []*dbt.Entity

		for _, assoc := range assocs {
			if assoc.ScopeChange {
				h.plugin.log.Info(assoc.Rationale)
				impacted = append(impacted, assoc.ImpactedAssets...)
			}
		}

		var assets []*dbt.Entity
		for _, im := range impacted {
			if a, hit := e.Session.Cache().GetAsset(im.Asset); hit && a != nil {
				assets = append(assets, a)
			} else if n := h.store(e, im.Asset, src); n != nil {
				assets = append(assets, n)
			}
		}

		if len(assets) > 0 {
			h.plugin.process(e, assets, src)
			h.plugin.addAssociatedRelationship(e, assocs)
		}
	}
	return nil
}

func (h *horfqdn) checkPTR(e *et.Event, edges []*dbt.Edge, fqdn *dbt.Entity, src *et.Source) {
	if rs, hit := e.Session.Cache().GetIncomingRelations(fqdn, "ptr_record"); hit && len(rs) > 0 {
		for _, r := range rs {
			ip, ok := r.FromAsset.Asset.(*oamnet.IPAddress)
			if !ok {
				continue
			}

			var inscope bool
			_, conf := e.Session.Scope().IsAssetInScope(ip, 0)
			if conf > 0 {
				inscope = true
			}

			for _, edge := range edges {
				if inscope {
					if dom, err := publicsuffix.EffectiveTLDPlusOne(edge.ToEntity.Asset.Key()); err == nil && dom != "" {
						if e.Session.Scope().AddDomain(dom) {
							h.plugin.log.Info(fmt.Sprintf("[%s: %s] was added to the session scope", "FQDN", dom))
						}
						h.plugin.submitFQDN(e, dom, src)
					}
				} else if _, conf := e.Session.Scope().IsAssetInScope(edge.ToEntity.Asset, 0); conf > 0 {
					if e.Session.Scope().Add(ip) {
						size := 100
						if e.Session.Config().Active {
							size = 250
						}
						h.plugin.submitIPAddresses(e, ip, src)
						support.IPAddressSweep(e, ip, src, size, h.plugin.submitIPAddresses)
						h.plugin.log.Info(fmt.Sprintf("[%s: %s] was added to the session scope", ip.AssetType(), ip.Key()))
					}
				}
			}
		}
	}
}

func (h *horfqdn) lookup(e *et.Event, asset *dbt.Entity, conf int) []*scope.Association {
	if assocs, err := e.Session.Scope().IsAssociated(e.Session.Cache(), &scope.Association{
		Submission:  asset,
		Confidence:  conf,
		ScopeChange: true,
	}); err == nil {
		return assocs
	}
	return []*scope.Association{}
}

func (h *horfqdn) store(e *et.Event, asset oam.Asset, src *et.Source) *dbt.Entity {
	a, err := e.Session.Cache().CreateAsset(asset)
	if err != nil || a == nil {
		return nil
	}

	_, _ = e.Session.Cache().CreateEntityProperty(a, &property.SourceProperty{
		Source:     src.Name,
		Confidence: src.Confidence,
	})
	return a
}
