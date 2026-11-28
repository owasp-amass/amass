// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package peeringdb reads PeeringDB, the database networks keep about
// themselves, for the autonomous systems an enumeration reaches: each
// network's operator organization, its website and address, and the
// operator's other networks (internal/semantics/peeringdb.json).
package peeringdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/time/rate"
)

// Properties of an autonomous system that PeeringDB records.
const (
	PropNetID       = "peeringdb_net_id"
	PropNetworkType = "network_type"
	PropPolicy      = "peering_policy"
	PropIRRASSet    = "irr_as_set"
)

type peeringDB struct {
	name    string
	log     *slog.Logger
	rlimit  *rate.Limiter
	source  *et.Source
	catalog semantics.PeeringDB
}

func NewPeeringDB() et.Plugin {
	c := semantics.PeeringDBCatalog()
	return &peeringDB{
		name:    "PeeringDB",
		rlimit:  rate.NewLimiter(rate.Every(time.Duration(c.RequestSeconds)*time.Second), 1),
		source:  &et.Source{Name: "PeeringDB", Confidence: 90},
		catalog: c,
	}
}

func (p *peeringDB) Name() string { return p.name }

func (p *peeringDB) Start(r et.Registry) error {
	p.log = r.Log().WithGroup("plugin").With("name", p.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       p,
		Name:         p.name + "-AS-Handler",
		Position:     6,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.ContactRecord), string(oam.AutonomousSystem)},
		EventType:    oam.AutonomousSystem,
		Callback:     p.check,
	}); err != nil {
		return err
	}

	p.log.Info("Plugin started")
	return nil
}

func (p *peeringDB) Stop() { p.log.Info("Plugin stopped") }

// network is a PeeringDB network record, as far as Amass reads it.
type network struct {
	ID       int    `json:"id"`
	OrgID    int    `json:"org_id"`
	ASN      int    `json:"asn"`
	Name     string `json:"name"`
	Website  string `json:"website"`
	IRRASSet string `json:"irr_as_set"`
	InfoType string `json:"info_type"`
	Policy   string `json:"policy_general"`
}

// organization is a PeeringDB organization record.
type organization struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Website  string `json:"website"`
	Address1 string `json:"address1"`
	Address2 string `json:"address2"`
	City     string `json:"city"`
	State    string `json:"state"`
	Zipcode  string `json:"zipcode"`
	Country  string `json:"country"`
}

func (p *peeringDB) check(e *et.Event) error {
	as, ok := e.Entity.Asset.(*oamnet.AutonomousSystem)
	if !ok {
		return errors.New("failed to extract the AutonomousSystem asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.AutonomousSystem), string(oam.ContactRecord),
		p.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, p.source, since) {
		return nil
	}

	nets, ok := p.networks(e, fmt.Sprintf("asn=%d", as.Number))
	if !ok {
		return nil
	}
	support.MarkAssetMonitored(e.Session, e.Entity, p.source)
	if len(nets) == 0 || nets[0].OrgID == 0 {
		return nil
	}

	net := nets[0]
	cr := p.operator(e, net.OrgID)
	if cr == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()
	p.storeNetwork(ctx, e.Session, e.Entity, cr, net)

	// the operator's other networks
	siblings, ok := p.networks(e, fmt.Sprintf("org_id=%d", net.OrgID))
	if !ok {
		return nil
	}
	n := 0
	for _, sib := range siblings {
		if sib.ASN <= 0 || sib.ASN == as.Number {
			continue
		}
		if n++; n > p.catalog.MaxNetworks {
			break
		}
		ent, err := e.Session.DB().CreateAsset(ctx, &oamnet.AutonomousSystem{Number: sib.ASN})
		if err != nil || ent == nil {
			continue
		}
		support.AddSource(ctx, e.Session, ent, p.source)
		p.storeNetwork(ctx, e.Session, ent, cr, sib)
	}
	return nil
}

// storeNetwork links an autonomous system to its operator's ContactRecord
// and records what its network record says about it.
func (p *peeringDB) storeNetwork(ctx context.Context, sess et.Session, as, cr *dbt.Entity, net network) {
	support.Link(ctx, sess, as, "contact", cr, p.source)
	support.AddProperty(ctx, sess, as, PropNetID, fmt.Sprint(net.ID))
	support.AddProperty(ctx, sess, as, PropNetworkType, strings.TrimSpace(net.InfoType))
	support.AddProperty(ctx, sess, as, PropPolicy, strings.TrimSpace(net.Policy))
	support.AddProperty(ctx, sess, as, PropIRRASSet, strings.TrimSpace(net.IRRASSet))
}

// operator stores the PeeringDB organization with id as a ContactRecord
// keyed by its PeeringDB page: the organization it names, its website and
// its address. The organization is dispatched.
func (p *peeringDB) operator(e *et.Event, id int) *dbt.Entity {
	var o organization
	if !p.get(e, fmt.Sprintf("%s%s%d", p.catalog.API, p.catalog.OrgPath, id), func(data json.RawMessage) bool {
		var orgs []organization
		if json.Unmarshal(data, &orgs) != nil || len(orgs) == 0 {
			return false
		}
		o = orgs[0]
		return true
	}) || strings.TrimSpace(o.Name) == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()
	page := fmt.Sprintf("%s%d", p.catalog.PageURL, id)
	cr, err := e.Session.DB().CreateAsset(ctx, &oamcon.ContactRecord{DiscoveredAt: page})
	if err != nil || cr == nil {
		return nil
	}
	support.AddSource(ctx, e.Session, cr, p.source)
	if site := strings.TrimSpace(o.Website); site != "" {
		_ = support.LinkContactValue(ctx, e.Session, cr, site, p.source)
	}
	if loc := support.ParseStreetAddressIn(o.address(), o.Country); loc != nil {
		_ = support.LinkAsset(ctx, e.Session, cr, "street_address", loc, p.source)
	}
	_ = org.LinkContactOrg(e, cr, o.Name, p.source)
	return cr
}

// address is the organization's postal address on one line.
func (o organization) address() string {
	var parts []string
	for _, f := range []string{o.Address1, o.Address2, o.City, strings.TrimSpace(o.State + " " + o.Zipcode),
		o.Country} {
		if f = strings.TrimSpace(f); f != "" {
			parts = append(parts, f)
		}
	}
	return strings.Join(parts, ", ")
}

// networks returns the network records that match query, and whether
// PeeringDB answered.
func (p *peeringDB) networks(e *et.Event, query string) ([]network, bool) {
	var nets []network
	ok := p.get(e, p.catalog.API+p.catalog.NetPath+"?"+query, func(data json.RawMessage) bool {
		return json.Unmarshal(data, &nets) == nil
	})
	return nets, ok
}

// get fetches a PeeringDB API answer and hands its data array to read.
func (p *peeringDB) get(e *et.Event, u string, read func(json.RawMessage) bool) bool {
	body, err := support.FetchBody(e, u, p.rlimit, 0)
	if err != nil {
		return false
	}
	var answer struct {
		Data json.RawMessage `json:"data"`
	}
	return json.Unmarshal(body, &answer) == nil && read(answer.Data)
}
