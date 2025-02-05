// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
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
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	var ptrs []*dbt.Edge
	if edges, err := e.Session.Cache().OutgoingEdges(e.Entity, e.Session.Cache().StartTime(), "dns_record"); err == nil {
		for _, edge := range edges {
			if rel, ok := edge.Relation.(*oamdns.BasicDNSRelation); ok && rel.Header.RRType == 12 {
				ptrs = append(ptrs, edge)
			}
		}
	}
	if len(ptrs) == 0 && !support.NameResolved(e.Session, fqdn) {
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

	if len(ptrs) > 0 {
		h.checkPTR(e, ptrs, e.Entity)
		return nil
	}

	if assocs := h.lookup(e, e.Entity, conf); len(assocs) > 0 {
		var impacted []*dbt.Entity

		for _, assoc := range assocs {
			if assoc.ScopeChange {
				h.plugin.log.Info(assoc.Rationale)
				impacted = append(impacted, assoc.ImpactedAssets...)
			}
		}

		var assets []*dbt.Entity
		for _, im := range impacted {
			if a, err := e.Session.Cache().FindEntitiesByContent(im.Asset,
				e.Session.Cache().StartTime()); err == nil && len(a) == 1 {
				assets = append(assets, a[0])
			} else if n := h.store(e, im.Asset); n != nil {
				assets = append(assets, n)
			}
		}

		if len(assets) > 0 {
			h.plugin.process(e, assets)
			h.plugin.addAssociatedRelationship(e, assocs)
		}
	}
	return nil
}

func (h *horfqdn) checkPTR(e *et.Event, edges []*dbt.Edge, fqdn *dbt.Entity) {
	if ins, err := e.Session.Cache().IncomingEdges(fqdn, e.Session.Cache().StartTime(), "ptr_record"); err == nil && len(ins) > 0 {
		for _, r := range ins {
			from, err := e.Session.Cache().FindEntityById(r.FromEntity.ID)
			if err != nil {
				continue
			}
			ip, ok := from.Asset.(*oamnet.IPAddress)
			if !ok {
				continue
			}

			var inscope bool
			_, conf := e.Session.Scope().IsAssetInScope(ip, 0)
			if conf > 0 {
				inscope = true
			}

			for _, edge := range edges {
				to, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID)
				if err != nil {
					continue
				}
				if inscope {
					if dom, err := publicsuffix.EffectiveTLDPlusOne(to.Asset.Key()); err == nil && dom != "" {
						if e.Session.Scope().AddDomain(dom) {
							h.plugin.log.Info(fmt.Sprintf("[%s: %s] was added to the session scope", "FQDN", dom))
						}
						h.plugin.submitFQDN(e, dom)
					}
				} else if _, conf := e.Session.Scope().IsAssetInScope(to.Asset, 0); conf > 0 {
					if e.Session.Scope().Add(ip) {
						size := 100
						if e.Session.Config().Active {
							size = 250
						}
						h.plugin.submitIPAddresses(e, ip, h.plugin.source)
						support.IPAddressSweep(e, ip, h.plugin.source, size, h.plugin.submitIPAddresses)
						h.plugin.log.Info(fmt.Sprintf("[%s: %s] was added to the session scope", ip.AssetType(), ip.Key()))
					}
				}
			}
		}
	}
}

func (h *horfqdn) lookup(e *et.Event, asset *dbt.Entity, conf int) []*scope.Association {
	assocs, err := e.Session.Scope().IsAssociated(e.Session.Cache(), &scope.Association{
		Submission:  asset,
		Confidence:  conf,
		ScopeChange: true,
	})
	if err != nil {
		return nil
	}
	return assocs
}

func (h *horfqdn) store(e *et.Event, asset oam.Asset) *dbt.Entity {
	a, err := e.Session.Cache().CreateAsset(asset)
	if err != nil || a == nil {
		return nil
	}

	_, _ = e.Session.Cache().CreateEntityProperty(a, &general.SourceProperty{
		Source:     h.plugin.source.Name,
		Confidence: h.plugin.source.Confidence,
	})
	return a
}
