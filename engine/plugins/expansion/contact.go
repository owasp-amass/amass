// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package expansion

import (
	"errors"
	"log/slog"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/source"
)

type contactrec struct {
	name       string
	log        *slog.Logger
	transforms []string
	source     *source.Source
}

func NewContacts() et.Plugin {
	return &contactrec{
		name: "Contract-Record-Expansion",
		transforms: []string{
			string(oam.URL),
			string(oam.Person),
			string(oam.Organization),
			string(oam.Location),
			string(oam.EmailAddress),
			string(oam.Phone),
		},
		source: &source.Source{
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
	_, ok := e.Asset.Asset.(*contact.ContactRecord)
	if !ok {
		return errors.New("failed to extract the ContactRecord asset")
	}

	matches, err := e.Session.Config().CheckTransformations(
		string(oam.ContactRecord), append(cr.transforms, cr.name)...)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	src := support.GetSource(e.Session, cr.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	if findings := cr.lookup(e, e.Asset, matches); len(findings) > 0 {
		cr.process(e, findings, src)
	}
	return nil
}

func (cr *contactrec) lookup(e *et.Event, asset *dbt.Asset, m *config.Matches) []*support.Finding {
	var rtypes []string
	confs := make(map[string]int)
	var findings []*support.Finding
	sinces := make(map[string]time.Time)

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
		case string(oam.EmailAddress):
			rtypes = append(rtypes, "email")
		case string(oam.Phone):
			rtypes = append(rtypes, "phone")
		case string(oam.URL):
			rtypes = append(rtypes, "url")
		}
	}

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		if rels, err := e.Session.DB().OutgoingRelations(asset, time.Time{}, rtypes...); err == nil && len(rels) > 0 {
			for _, rel := range rels {
				a, err := e.Session.DB().FindById(rel.ToAsset.ID, time.Time{})
				if err != nil {
					continue
				}

				totype := string(a.Asset.AssetType())
				if since, ok := sinces[totype]; !ok || (ok && a.LastSeen.Before(since)) {
					continue
				}

				conrec := asset.Asset.(*contact.ContactRecord)
				findings = append(findings, &support.Finding{
					From:     asset,
					FromName: "ContactRecord: " + conrec.DiscoveredAt,
					To:       a,
					ToName:   a.Asset.Key(),
					Rel:      rel.Type,
				})
			}
		}
	})
	<-done
	close(done)
	return findings
}

func (cr *contactrec) process(e *et.Event, findings []*support.Finding, src *dbt.Asset) {
	support.ProcessAssetsWithSource(e, findings, src, cr.name, cr.name+"-Handler")
}
