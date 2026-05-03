// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

type horizPlugin struct {
	name        string
	log         *slog.Logger
	horfqdn     *horfqdn
	horaddr     *horaddr
	horOrg      *horOrg
	horLocation *horLocation
	horRegRec   *horRegRec
	horTlsCert  *horTlsCert
	source      *et.Source
}

func NewHorizontals() et.Plugin {
	return &horizPlugin{
		name: "Horizontals",
		source: &et.Source{
			Name:       "Horizontals",
			Confidence: 75,
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
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     h.horfqdn.check,
	}); err != nil {
		return err
	}

	h.horaddr = &horaddr{
		name:   h.name + "-IPAddress-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horaddr.name,
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.IPAddress)},
		EventType:    oam.IPAddress,
		Callback:     h.horaddr.check,
	}); err != nil {
		return err
	}

	h.horOrg = &horOrg{
		name:   h.name + "-Organization-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horOrg.name,
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Organization)},
		EventType:    oam.Organization,
		Callback:     h.horOrg.check,
	}); err != nil {
		return err
	}

	h.horLocation = &horLocation{
		name:   h.name + "-Location-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horLocation.name,
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Location)},
		EventType:    oam.Location,
		Callback:     h.horLocation.check,
	}); err != nil {
		return err
	}

	h.horRegRec = &horRegRec{
		name:   h.name + "-Registration-Record-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horRegRec.name,
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.AutnumRecord)},
		EventType:    oam.AutnumRecord,
		Callback:     h.horRegRec.check,
	}); err != nil {
		return err
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horRegRec.name,
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.DomainRecord)},
		EventType:    oam.DomainRecord,
		Callback:     h.horRegRec.check,
	}); err != nil {
		return err
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horRegRec.name,
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.IPNetRecord)},
		EventType:    oam.IPNetRecord,
		Callback:     h.horRegRec.check,
	}); err != nil {
		return err
	}

	h.horTlsCert = &horTlsCert{
		name:   h.name + "-TLS-Certificate-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horTlsCert.name,
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.TLSCertificate)},
		EventType:    oam.TLSCertificate,
		Callback:     h.horTlsCert.check,
	}); err != nil {
		return err
	}

	h.log.Info("Plugin started")
	return nil
}

func (h *horizPlugin) Stop() {
	h.log.Info("Plugin stopped")
}

func (h *horizPlugin) submitIPAddress(e *et.Event, asset *oamnet.IPAddress, src *et.Source) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	// ensure we do not work on an IP address that was processed previously
	_, err := e.Session.DB().FindEntitiesByContent(ctx, oam.IPAddress, e.Session.StartTime(), 1, dbt.ContentFilters{
		"address": asset.Address.String(),
	})
	if err == nil {
		return
	}

	addr, err := e.Session.DB().CreateAsset(ctx, asset)
	if err == nil && addr != nil {
		_, _ = e.Session.DB().CreateEntityProperty(ctx, addr, &oamgen.SourceProperty{
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

func (h *horizPlugin) getContactRecord(sess et.Session, ent *dbt.Entity, label string) (*dbt.Entity, error) {
	since, err := support.TTLStartTime(sess.Config(),
		string(ent.Asset.AssetType()), string(oam.ContactRecord), h.name)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	edges, err := sess.DB().OutgoingEdges(ctx, ent, since, label)
	if err != nil || len(edges) == 0 {
		return nil, errors.New("failed to obtain the contact record")
	}

	to, err := sess.DB().FindEntityById(ctx, edges[0].ToEntity.ID)
	if err != nil {
		return nil, err
	}

	if _, valid := to.Asset.(*oamcon.ContactRecord); valid {
		return to, nil
	}
	return nil, errors.New("failed to cast the ContactRecord entity")
}

func (h *horizPlugin) lookupContactRecordOrgsAndLocations(sess et.Session, cr *dbt.Entity) ([]*dbt.Entity, []*dbt.Entity) {
	var orgents []*dbt.Entity

	if ents, err := h.getContactRecordOrganizations(sess, cr); err == nil && len(ents) > 0 {
		for _, ent := range ents {
			if _, valid := ent.Asset.(*oamorg.Organization); valid {
				orgents = append(orgents, ent)
			}
		}
	}

	set := stringset.New()
	defer set.Close()

	var locents []*dbt.Entity
	for _, o := range orgents {
		if ents, err := h.getOrganizationLocations(sess, o); err == nil && len(ents) > 0 {
			for _, ent := range ents {
				if set.Has(ent.ID) {
					continue
				}
				if _, valid := ent.Asset.(*oamcon.Location); valid {
					set.Insert(ent.ID)
					locents = append(locents, ent)
				}
			}
		}
	}

	if ents, err := h.getContactRecordLocations(sess, cr); err == nil && len(ents) > 0 {
		for _, ent := range ents {
			if set.Has(ent.ID) {
				continue
			}
			if _, valid := ent.Asset.(*oamcon.Location); valid {
				set.Insert(ent.ID)
				locents = append(locents, ent)
			}
		}
	}

	return orgents, locents
}

func (h *horizPlugin) getContactRecordOrganizations(sess et.Session, cr *dbt.Entity) ([]*dbt.Entity, error) {
	since, err := support.TTLStartTime(sess.Config(),
		string(oam.ContactRecord), string(oam.Organization), h.name)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 5*time.Second)
	defer cancel()

	edges, err := sess.DB().OutgoingEdges(ctx, cr, since, "organization")
	if err != nil || len(edges) == 0 {
		return nil, errors.New("zero organizations found")
	}

	seconds := 5 * len(edges)
	octx, cancel := context.WithTimeout(sess.Ctx(), time.Duration(seconds)*time.Second)
	defer cancel()

	var results []*dbt.Entity
	for _, edge := range edges {
		to, err := sess.DB().FindEntityById(octx, edge.ToEntity.ID)
		if err != nil {
			continue
		}

		if _, valid := to.Asset.(*oamorg.Organization); valid {
			results = append(results, to)
		}
	}

	if len(results) == 0 {
		return nil, errors.New("failed to extract the organization")
	}
	return results, nil
}

func (h *horizPlugin) getContactRecordLocations(sess et.Session, cr *dbt.Entity) ([]*dbt.Entity, error) {
	since, err := support.TTLStartTime(sess.Config(),
		string(oam.ContactRecord), string(oam.Location), h.name)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 5*time.Second)
	defer cancel()

	edges, err := sess.DB().OutgoingEdges(ctx, cr, since, "location")
	if err != nil || len(edges) == 0 {
		return nil, errors.New("zero locations found")
	}

	seconds := 5 * len(edges)
	lctx, cancel := context.WithTimeout(sess.Ctx(), time.Duration(seconds)*time.Second)
	defer cancel()

	var results []*dbt.Entity
	for _, edge := range edges {
		to, err := sess.DB().FindEntityById(lctx, edge.ToEntity.ID)
		if err != nil {
			continue
		}

		if _, valid := to.Asset.(*oamcon.Location); valid {
			results = append(results, to)
		}
	}

	if len(results) == 0 {
		return nil, errors.New("failed to extract the locations")
	}
	return results, nil
}

func (h *horizPlugin) getOrganizationLocations(sess et.Session, o *dbt.Entity) ([]*dbt.Entity, error) {
	since, err := support.TTLStartTime(sess.Config(),
		string(oam.Organization), string(oam.Location), h.name)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 5*time.Second)
	defer cancel()

	edges, err := sess.DB().OutgoingEdges(ctx, o, since, "hq_address", "location")
	if err != nil || len(edges) == 0 {
		return nil, errors.New("zero locations found")
	}

	seconds := 5 * len(edges)
	lctx, cancel := context.WithTimeout(sess.Ctx(), time.Duration(seconds)*time.Second)
	defer cancel()

	var results []*dbt.Entity
	for _, edge := range edges {
		to, err := sess.DB().FindEntityById(lctx, edge.ToEntity.ID)
		if err != nil {
			continue
		}

		if _, valid := to.Asset.(*oamcon.Location); valid {
			results = append(results, to)
		}
	}

	if len(results) == 0 {
		return nil, errors.New("failed to extract the locations")
	}
	return results, nil
}

func (h *horizPlugin) addASNetblocksToScope(sess et.Session, asn int) *dbt.Entity {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	var as *dbt.Entity
	if ents, err := sess.DB().FindEntitiesByContent(ctx, oam.AutonomousSystem, time.Time{}, 1, dbt.ContentFilters{
		"number": asn,
	}); err == nil && len(ents) == 1 {
		as = ents[0]
	}
	if as == nil {
		return nil
	}

	since, err := support.TTLStartTime(sess.Config(), string(oam.AutonomousSystem), string(oam.Netblock), h.name)
	if err != nil {
		return as
	}

	if edges, err := sess.DB().OutgoingEdges(ctx, as, since, "announces"); err == nil && len(edges) > 0 {
		seconds := 5 * len(edges)

		ctx, cancel := context.WithTimeout(sess.Ctx(), time.Duration(seconds)*time.Second)
		defer cancel()

		for _, edge := range edges {
			if to, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && to != nil {
				// add the announced netblock to the scope
				h.enqueueIfOutOfScope(sess, to)
			}
		}
	}

	return as
}

func (h *horizPlugin) confidence(sess et.Session, atype oam.AssetType) int {
	tstr := string(atype)

	if matches, err := sess.Config().CheckTransformations(tstr, tstr); err == nil && matches != nil {
		if conf := matches.Confidence(h.name); conf > 0 {
			return conf
		}
		if conf := matches.Confidence(tstr); conf > 0 {
			return conf
		}
	}

	return -1
}

func (h *horizPlugin) isEntityInScope(sess et.Session, ent *dbt.Entity) bool {
	econf := h.confidence(sess, ent.Asset.AssetType())
	if econf <= 0 {
		return false
	}

	if _, conf := sess.Scope().IsAssetInScope(ent.Asset, econf); conf >= econf {
		return true
	}
	return false
}

func (h *horizPlugin) addToScopeAndEnqueue(sess et.Session, ent *dbt.Entity) {
	if sess.Scope().Add(ent.Asset) {
		if econf := h.confidence(sess, ent.Asset.AssetType()); econf > 0 {
			if a, conf := sess.Scope().IsAssetInScope(ent.Asset, econf); conf >= econf {
				if strings.EqualFold(a.Key(), ent.Asset.Key()) {
					_ = sess.Backlog().Enqueue(ent)
				}
			}
		}
	}
}

func (h *horizPlugin) enqueueIfOutOfScope(sess et.Session, ent *dbt.Entity) {
	if !h.isEntityInScope(sess, ent) {
		h.addToScopeAndEnqueue(sess, ent)
	}
}

func (h *horizPlugin) getRegisteredDomainEntity(sess et.Session, record *dbt.Entity) (*dbt.Entity, error) {
	dr, valid := record.Asset.(*oamreg.DomainRecord)
	if !valid {
		return nil, errors.New("failed to cast the DomainRecord")
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	if ents, err := sess.DB().FindEntitiesByContent(ctx, oam.FQDN, time.Time{}, 1, dbt.ContentFilters{
		"name": dr.Domain,
	}); err == nil && len(ents) == 1 {
		return ents[0], nil
	}

	return nil, fmt.Errorf("failed to obtain the registered domain name FQDN for: %s", dr.Domain)
}

func (h *horizPlugin) getRegisteredNetblockEntity(sess et.Session, record *dbt.Entity) (*dbt.Entity, error) {
	iprec, valid := record.Asset.(*oamreg.IPNetRecord)
	if !valid {
		return nil, errors.New("failed to cast the IPNetRecord")
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	if ents, err := sess.DB().FindEntitiesByContent(ctx, oam.Netblock, time.Time{}, 1, dbt.ContentFilters{
		"cidr": iprec.CIDR.String(),
	}); err == nil && len(ents) == 1 {
		return ents[0], nil
	}

	return nil, fmt.Errorf("failed to obtain the registered CIDR Netblock for: %s", iprec.CIDR.String())
}
