// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package expansion

import (
	"errors"
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
)

type contactrec struct {
	name       string
	log        *slog.Logger
	transforms []string
	source     *et.Source
}

func NewContacts() et.Plugin {
	return &contactrec{
		name: "Contract-Record-Expansion",
		transforms: []string{
			string(oam.URL),
			string(oam.Person),
			string(oam.Organization),
			string(oam.Location),
			string(oam.Identifier),
			string(oam.Phone),
		},
		source: &et.Source{
			Name:       "Contract-Record-Expansion",
			Confidence: 100,
		},
	}
}

func (cr *contactrec) Name() string {
	return cr.name
}

func (cr *contactrec) Start(r et.Registry) error {
	cr.log = r.Log().WithGroup("plugin").With("name", cr.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     cr,
		Name:       cr.name,
		Priority:   1,
		Transforms: cr.transforms,
		EventType:  oam.ContactRecord,
		Callback:   cr.check,
	}); err != nil {
		return err
	}

	cr.log.Info("Plugin started")
	return nil
}

func (cr *contactrec) Stop() {
	cr.log.Info("Plugin stopped")
}

func (cr *contactrec) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*contact.ContactRecord)
	if !ok {
		return errors.New("failed to extract the ContactRecord asset")
	}

	matches, err := e.Session.Config().CheckTransformations(
		string(oam.ContactRecord), append(cr.transforms, cr.name)...)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	if findings := cr.lookup(e, e.Entity, matches); len(findings) > 0 {
		cr.process(e, findings)
	}
	return nil
}

func (cr *contactrec) lookup(e *et.Event, entity *dbt.Entity, m *config.Matches) []*support.Finding {
	var rtypes []string
	confs := make(map[string]int)
	sinces := make(map[string]time.Time)
	conrec := entity.Asset.(*contact.ContactRecord)

	for _, atype := range cr.transforms {
		if !m.IsMatch(atype) {
			continue
		}

		since, err := support.TTLStartTime(e.Session.Config(), string(oam.ContactRecord), atype, cr.name)
		if err != nil {
			continue
		}
		sinces[atype] = since

		confs[atype] = m.Confidence(atype)
		if confs[atype] == -1 {
			confs[atype] = 0
		}

		switch atype {
		case string(oam.Person):
			rtypes = append(rtypes, "person")
		case string(oam.Organization):
			rtypes = append(rtypes, "organization")
		case string(oam.Location):
			rtypes = append(rtypes, "location")
		case string(oam.Identifier):
			rtypes = append(rtypes, "id")
		case string(oam.Phone):
			rtypes = append(rtypes, "phone")
		case string(oam.URL):
			rtypes = append(rtypes, "url")
		}
	}

	var findings []*support.Finding
	if edges, err := e.Session.Cache().OutgoingEdges(entity, time.Time{}, rtypes...); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID)
			if err != nil {
				continue
			}

			totype := string(a.Asset.AssetType())
			if since, ok := sinces[totype]; !ok || (ok && a.LastSeen.Before(since)) {
				continue
			}

			findings = append(findings, &support.Finding{
				From:     entity,
				FromName: "ContactRecord: " + conrec.DiscoveredAt,
				To:       a,
				ToName:   a.Asset.Key(),
				Rel:      edge.Relation,
			})
		}
	}
	return findings
}

func (cr *contactrec) process(e *et.Event, findings []*support.Finding) {
	support.ProcessAssetsWithSource(e, findings, cr.source, cr.name, cr.name+"-Handler")
}
