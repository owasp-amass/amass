// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	"github.com/owasp-amass/amass/v4/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/resolve"
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
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
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

	src := support.GetSource(e.Session, h.plugin.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	matches, err := e.Session.Config().CheckTransformations(string(oam.FQDN), string(oam.FQDN), h.plugin.name)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	conf := matches.Confidence(h.plugin.name)
	if conf == -1 {
		conf = matches.Confidence(string(oam.FQDN))
	}

	if hit && len(rels) > 0 {
		h.checkPTR(e, fqdn.Name, rels, src)
		return nil
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

func (h *horfqdn) checkPTR(e *et.Event, name string, rels []*dbt.Relation, src *dbt.Asset) {
	if ipstr := dnsutil.ExtractAddressFromReverse(name + "."); ipstr != "" {
		ipstr = resolve.RemoveLastDot(ipstr)

		addr, err := netip.ParseAddr(ipstr)
		if err != nil {
			return
		}

		ip := &oamnet.IPAddress{Address: addr, Type: "IPv4"}
		if ip.Address.Is6() {
			ip.Type = "IPv6"
		}

		var inscope bool
		_, conf := e.Session.Scope().IsAssetInScope(ip, 0)
		if conf > 0 {
			inscope = true
		}

		for _, rel := range rels {
			if inscope {
				if dom, err := publicsuffix.EffectiveTLDPlusOne(rel.ToAsset.Asset.Key()); err == nil && dom != "" {
					if e.Session.Scope().AddDomain(dom) {
						h.plugin.log.Info(fmt.Sprintf("[%s: %s] was added to the session scope", "FQDN", dom))
					}
					h.plugin.submitFQDN(e, dom, src)
				}
			} else if _, conf := e.Session.Scope().IsAssetInScope(rel.ToAsset.Asset, 0); conf > 0 {
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

func (h *horfqdn) lookup(e *et.Event, asset *dbt.Asset, conf int) []*scope.Association {
	if assocs, err := e.Session.Scope().IsAssociated(e.Session.Cache(), &scope.Association{
		Submission:  asset,
		Confidence:  conf,
		ScopeChange: true,
	}); err == nil {
		return assocs
	}
	return []*scope.Association{}
}

func (h *horfqdn) store(e *et.Event, asset oam.Asset, src *dbt.Asset) *dbt.Asset {
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
