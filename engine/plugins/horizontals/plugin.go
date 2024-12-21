// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"fmt"
	"log/slog"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	"github.com/owasp-amass/amass/v4/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/property"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/relation"
	"github.com/owasp-amass/resolve"
	"golang.org/x/net/publicsuffix"
)

type horizPlugin struct {
	name       string
	log        *slog.Logger
	horfqdn    *horfqdn
	horContact *horContact
	source     *et.Source
}

func NewHorizontals() et.Plugin {
	return &horizPlugin{
		name: "Horizontals",
		source: &et.Source{
			Name:       "Horizontals",
			Confidence: 50,
		},
	}
}

func (h *horizPlugin) Name() string {
	return h.name
}

func (h *horizPlugin) Start(r et.Registry) error {
	h.log = r.Log().WithGroup("plugin").With("name", h.name)

	h.horfqdn = &horfqdn{
		name:   h.name + "-FQDN-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horfqdn.name,
		Priority:     3,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     h.horfqdn.check,
	}); err != nil {
		return err
	}

	h.horContact = &horContact{
		name:   h.name + "-ContactRecord-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     h,
		Name:       h.horContact.name,
		Transforms: []string{string(oam.ContactRecord)},
		EventType:  oam.ContactRecord,
		Callback:   h.horContact.check,
	}); err != nil {
		return err
	}

	h.log.Info("Plugin started")
	return nil
}

func (h *horizPlugin) Stop() {
	h.log.Info("Plugin stopped")
}

func (h *horizPlugin) addAssociatedRelationship(e *et.Event, assocs []*scope.Association) {
	for _, assoc := range assocs {
		for _, impacted := range assoc.ImpactedAssets {
			conf := 50

			if e.Session.Config().DefaultTransformations != nil {
				if c := e.Session.Config().DefaultTransformations.Confidence; c > 0 {
					conf = c
				}
			}

			if match, result := e.Session.Scope().IsAssetInScope(impacted.Asset, conf); result >= conf && match != nil {
				if a, err := e.Session.Cache().FindEntitiesByContent(match, e.Session.Cache().StartTime()); err == nil && len(a) == 1 {
					for _, assoc2 := range e.Session.Scope().AssetsWithAssociation(e.Session.Cache(), a[0]) {
						h.makeAssocRelationshipEntries(e, assoc.Match, assoc2)
					}
				}
			}
		}
	}
}

func (h *horizPlugin) makeAssocRelationshipEntries(e *et.Event, assoc, assoc2 *dbt.Entity) {
	// do not connect an asset to itself
	if assoc.ID == assoc2.ID {
		return
	}

	_, _ = e.Session.Cache().CreateEdge(&dbt.Edge{
		Relation:   &relation.SimpleRelation{Name: "associated_with"},
		FromEntity: assoc,
		ToEntity:   assoc2,
	})
	_, _ = e.Session.Cache().CreateEdge(&dbt.Edge{
		Relation:   &relation.SimpleRelation{Name: "associated_with"},
		FromEntity: assoc2,
		ToEntity:   assoc,
	})
}

func (h *horizPlugin) process(e *et.Event, assets []*dbt.Entity) {
	for _, asset := range assets {
		// check for new networks added to the scope
		switch v := asset.Asset.(type) {
		case *oamnet.Netblock:
			h.ipPTRTargetsInScope(e, asset)
			h.sweepAroundIPs(e, asset)
			//h.sweepNetblock(e, v, src)
		case *oamreg.IPNetRecord:
			if ents, err := e.Session.Cache().FindEntitiesByContent(
				&oamnet.Netblock{CIDR: v.CIDR, Type: v.Type}, e.Session.Cache().StartTime()); err == nil && len(ents) == 1 {
				a := ents[0]

				if _, ok := a.Asset.(*oamnet.Netblock); ok {
					h.ipPTRTargetsInScope(e, a)
					h.sweepAroundIPs(e, a)
					//h.sweepNetblock(e, nb, src)
				}
			}
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    asset.Asset.Key(),
			Entity:  asset,
			Session: e.Session,
		})

		_, _ = e.Session.Cache().CreateEntityProperty(asset, &property.SourceProperty{
			Source:     h.source.Name,
			Confidence: h.source.Confidence,
		})
	}
}

func (h *horizPlugin) ipPTRTargetsInScope(e *et.Event, nb *dbt.Entity) {
	if edges, err := e.Session.Cache().OutgoingEdges(nb, e.Session.Cache().StartTime(), "contains"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			to, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID)
			if err != nil {
				continue
			}

			reverse, err := dns.ReverseAddr(to.Asset.Key())
			if err != nil {
				continue
			}

			if ents, err := e.Session.Cache().FindEntitiesByContent(
				&domain.FQDN{Name: resolve.RemoveLastDot(reverse)}, e.Session.Cache().StartTime()); err == nil && len(ents) == 1 {
				a := ents[0]

				if edges, err := e.Session.Cache().OutgoingEdges(a, e.Session.Cache().StartTime(), "dns_record"); err == nil && len(edges) > 0 {
					for _, edge := range edges {
						if rel, ok := edge.Relation.(*relation.BasicDNSRelation); !ok || rel.Header.RRType != 12 {
							continue
						}
						to, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID)
						if err != nil {
							continue
						}
						if dom, err := publicsuffix.EffectiveTLDPlusOne(to.Asset.Key()); err == nil {
							if e.Session.Scope().AddDomain(dom) {
								h.submitFQDN(e, dom)
								h.log.Info(fmt.Sprintf("[%s: %s] was added to the session scope", "FQDN", dom))
							}
						}
					}
				}
			}
		}
	}
}

func (h *horizPlugin) sweepAroundIPs(e *et.Event, nb *dbt.Entity) {
	if edges, err := e.Session.Cache().OutgoingEdges(nb, e.Session.Cache().StartTime(), "contains"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			size := 100
			if e.Session.Config().Active {
				size = 250
			}

			to, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID)
			if err != nil {
				continue
			}
			if ip, ok := to.Asset.(*oamnet.IPAddress); ok {
				support.IPAddressSweep(e, ip, h.source, size, h.submitIPAddresses)
			}
		}
	}
}

/*
	func (h *horizPlugin) sweepNetblock(e *et.Event, nb *oamnet.Netblock, src *et.Source) {
		for _, ip := range h.inScopeNetblockIPs(nb) {
			h.submitIPAddresses(e, ip, src)
		}
	}

	func (h *horizPlugin) inScopeNetblockIPs(nb *oamnet.Netblock) []*oamnet.IPAddress {
		_, cidr, err := net.ParseCIDR(nb.CIDR.String())
		if err != nil {
			return []*oamnet.IPAddress{}
		}

		var ips []net.IP
		if nb.CIDR.Masked().Bits() > 20 {
			ips = amassnet.AllHosts(cidr)
		} else {
			ips = h.distAcrossNetblock(cidr, 2048)
		}

		var results []*oamnet.IPAddress
		for _, ip := range ips {
			addr := &oamnet.IPAddress{Address: netip.MustParseAddr(ip.String()), Type: "IPv4"}
			if addr.Address.Is6() {
				addr.Type = "IPv6"
			}
			results = append(results, addr)
		}
		return results
	}

	func (h *horizPlugin) distAcrossNetblock(cidr *net.IPNet, num int) []net.IP {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		_, bits := cidr.Mask.Size()
		if bits == 0 {
			return []net.IP{}
		}

		total := 1 << bits
		inc := total / num
		var results []net.IP
		for ip := cidr.IP.Mask(cidr.Mask); cidr.Contains(ip); {
			sel := r.Intn(inc)

			for i := 0; i < inc; i++ {
				if i == sel {
					results = append(results, net.ParseIP(ip.String()))
				}
				amassnet.IPInc(ip)
			}
		}
		return results
	}
*/
func (h *horizPlugin) submitIPAddresses(e *et.Event, asset *oamnet.IPAddress, src *et.Source) {
	addr, err := e.Session.Cache().CreateAsset(asset)
	if err == nil && addr != nil {
		_, _ = e.Session.Cache().CreateEntityProperty(addr, &property.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    addr.Asset.Key(),
			Entity:  addr,
			Session: e.Session,
		})
	}
}

func (h *horizPlugin) submitFQDN(e *et.Event, dom string) {
	fqdn, err := e.Session.Cache().CreateAsset(&domain.FQDN{Name: dom})
	if err == nil && fqdn != nil {
		_, _ = e.Session.Cache().CreateEntityProperty(fqdn, &property.SourceProperty{
			Source:     h.source.Name,
			Confidence: h.source.Confidence,
		})
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    fqdn.Asset.Key(),
			Entity:  fqdn,
			Session: e.Session,
		})
	}
}
