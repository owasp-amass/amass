// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	"github.com/owasp-amass/amass/v4/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v4/engine/types"
	amassnet "github.com/owasp-amass/amass/v4/utils/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
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
				if a, hit := e.Session.Cache().GetAsset(match); hit && a != nil {
					for _, assoc2 := range e.Session.Scope().AssetsWithAssociation(e.Session.Cache(), a) {
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
	// check that this relationship has not already been setup during this session
	if rels, hit := e.Session.Cache().GetOutgoingRelations(assoc, "associated_with"); hit && len(rels) > 0 {
		for _, rel := range rels {
			if rel.ToAsset.ID == assoc2.ID {
				return
			}
		}
	}

	now := time.Now()
	e.Session.Cache().SetRelation(&dbt.Relation{
		Type:      "associated_with",
		CreatedAt: now,
		LastSeen:  now,
		FromAsset: assoc,
		ToAsset:   assoc2,
	})
	e.Session.Cache().SetRelation(&dbt.Relation{
		Type:      "associated_with",
		CreatedAt: now,
		LastSeen:  now,
		FromAsset: assoc2,
		ToAsset:   assoc,
	})

	done := make(chan struct{}, 1)
	defer close(done)

	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		_, _ = e.Session.DB().Link(assoc, "associated_with", assoc2)
		_, _ = e.Session.DB().Link(assoc2, "associated_with", assoc)
	})
	<-done
}

func (h *horizPlugin) process(e *et.Event, assets []*dbt.Asset, src *dbt.Asset) {
	for _, asset := range assets {
		// check for new networks added to the scope
		switch v := asset.Asset.(type) {
		case *oamnet.Netblock:
			h.ipPTRTargetsInScope(e, asset, src)
			h.sweepAroundIPs(e, asset, src)
			//h.sweepNetblock(e, v, src)
		case *oamreg.IPNetRecord:
			if a, hit := e.Session.Cache().GetAsset(&oamnet.Netblock{CIDR: v.CIDR, Type: v.Type}); hit && a != nil {
				if _, ok := a.Asset.(*oamnet.Netblock); ok {
					h.ipPTRTargetsInScope(e, a, src)
					h.sweepAroundIPs(e, a, src)
					//h.sweepNetblock(e, nb, src)
				}
			}
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    asset.Asset.Key(),
			Asset:   asset,
			Session: e.Session,
		})

		if a, hit := e.Session.Cache().GetAsset(asset.Asset); hit && a != nil {
			now := time.Now()
			e.Session.Cache().SetRelation(&dbt.Relation{
				Type:      "source",
				CreatedAt: now,
				LastSeen:  now,
				FromAsset: a,
				ToAsset:   src,
			})
		}
	}
}

func (h *horizPlugin) ipPTRTargetsInScope(e *et.Event, nb, src *dbt.Asset) {
	if rels, hit := e.Session.Cache().GetOutgoingRelations(nb, "contains"); hit && len(rels) > 0 {
		for _, rel := range rels {
			reverse, err := dns.ReverseAddr(rel.ToAsset.Asset.Key())
			if err != nil {
				continue
			}

			if a, hit := e.Session.Cache().GetAsset(&domain.FQDN{Name: resolve.RemoveLastDot(reverse)}); hit && a != nil {
				if rels, hit := e.Session.Cache().GetOutgoingRelations(a, "ptr_record"); hit && len(rels) > 0 {
					for _, rel := range rels {
						if dom, err := publicsuffix.EffectiveTLDPlusOne(rel.ToAsset.Asset.Key()); err == nil {
							if e.Session.Scope().AddDomain(dom) {
								h.submitFQDN(e, dom, src)
								h.log.Info(fmt.Sprintf("[%s: %s] was added to the session scope", "FQDN", dom))
							}
						}
					}
				}
			}
		}
	}
}

func (h *horizPlugin) sweepAroundIPs(e *et.Event, nb, src *dbt.Asset) {
	if rels, hit := e.Session.Cache().GetOutgoingRelations(nb, "contains"); hit && len(rels) > 0 {
		for _, rel := range rels {
			size := 100
			if e.Session.Config().Active {
				size = 250
			}

			if ip, ok := rel.ToAsset.Asset.(*oamnet.IPAddress); ok {
				support.IPAddressSweep(e, ip, src, size, h.submitIPAddresses)
			}
		}
	}
}

func (h *horizPlugin) sweepNetblock(e *et.Event, nb *oamnet.Netblock, src *dbt.Asset) {
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

func (h *horizPlugin) submitIPAddresses(e *et.Event, asset *oamnet.IPAddress, src *dbt.Asset) {
	done := make(chan *dbt.Asset, 1)
	defer close(done)

	if _, hit := e.Session.Cache().GetAsset(asset); hit {
		return
	}

	support.AppendToDBQueue(func() {
		if e.Session.Done() {
			done <- nil
			return
		}

		addr, err := e.Session.DB().Create(nil, "", asset)
		if err == nil && addr != nil {
			_, _ = e.Session.DB().Link(addr, "source", src)
		}
		done <- addr
	})

	if a := <-done; a != nil {
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    a.Asset.Key(),
			Asset:   a,
			Session: e.Session,
		})
	}
}

func (h *horizPlugin) submitFQDN(e *et.Event, dom string, src *dbt.Asset) {
	done := make(chan *dbt.Asset, 1)
	defer close(done)

	fqdn := &domain.FQDN{Name: dom}
	if _, hit := e.Session.Cache().GetAsset(fqdn); hit {
		return
	}

	support.AppendToDBQueue(func() {
		if e.Session.Done() {
			done <- nil
			return
		}

		a, err := e.Session.DB().Create(nil, "", fqdn)
		if err == nil && a != nil {
			_, _ = e.Session.DB().Link(a, "source", src)
		}
		done <- a
	})

	if a := <-done; a != nil {
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    a.Asset.Key(),
			Asset:   a,
			Session: e.Session,
		})
	}
}
