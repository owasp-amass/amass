// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package expansion

import (
	"errors"
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/source"
)

type emailexpand struct {
	name   string
	log    *slog.Logger
	source *source.Source
}

func NewEmails() et.Plugin {
	return &emailexpand{
		name: "Email-Expansion",
		source: &source.Source{
			Name:       "Email-Expansion",
			Confidence: 100,
		},
	}
}

func (ee *emailexpand) Name() string {
	return ee.name
}

func (ee *emailexpand) Start(r et.Registry) error {
	ee.log = r.Log().WithGroup("plugin").With("name", ee.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     ee,
		Name:       ee.name,
		Transforms: []string{string(oam.FQDN)},
		EventType:  oam.EmailAddress,
		Callback:   ee.check,
	}); err != nil {
		return err
	}

	ee.log.Info("Plugin started")
	return nil
}

func (ee *emailexpand) Stop() {
	ee.log.Info("Plugin stopped")
}

func (ee *emailexpand) check(e *et.Event) error {
	oame, ok := e.Asset.Asset.(*contact.EmailAddress)
	if !ok {
		return errors.New("failed to extract the EmailAddress asset")
	}

	src := support.GetSource(e.Session, ee.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.EmailAddress), string(oam.FQDN), ee.name)
	if err != nil {
		return err
	}

	var findings []*support.Finding
	_, conf := e.Session.Scope().IsAssetInScope(oame, 0)
	inscope := conf > 0
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		if inscope {
			findings = append(findings, ee.lookup(e, e.Asset, since)...)
		}
	} else {
		findings = append(findings, ee.store(e, e.Asset, src)...)
		support.MarkAssetMonitored(e.Session, e.Asset, src)
	}

	if len(findings) > 0 && inscope {
		ee.process(e, findings, src)
	}
	return nil
}

func (ee *emailexpand) lookup(e *et.Event, asset *dbt.Asset, since time.Time) []*support.Finding {
	var findings []*support.Finding

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		if rels, err := e.Session.DB().OutgoingRelations(asset, since, string(oam.FQDN)); err == nil && len(rels) > 0 {
			for _, rel := range rels {
				if a, err := e.Session.DB().FindById(rel.ToAsset.ID, since); err == nil && a != nil {
					findings = append(findings, &support.Finding{
						From:     asset,
						FromName: "EmailAddress: " + asset.Asset.Key(),
						To:       a,
						ToName:   a.Asset.Key(),
						Rel:      rel.Type,
					})
				}
			}
		}
	})
	<-done
	close(done)
	return findings
}

func (ee *emailexpand) store(e *et.Event, asset, src *dbt.Asset) []*support.Finding {
	oame := asset.Asset.(*contact.EmailAddress)
	var findings []*support.Finding

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		if a, err := e.Session.DB().Create(asset, "domain", &domain.FQDN{
			Name: oame.Domain,
		}); err == nil && a != nil {
			_, _ = e.Session.DB().Link(a, "source", src)
			findings = append(findings, &support.Finding{
				From:     asset,
				FromName: "EmailAddress: " + asset.Asset.Key(),
				To:       a,
				ToName:   a.Asset.Key(),
				Rel:      "domain",
			})
		}
	})
	<-done
	close(done)
	return findings
}

func (ee *emailexpand) process(e *et.Event, findings []*support.Finding, src *dbt.Asset) {
	support.ProcessAssetsWithSource(e, findings, src, ee.name, ee.name+"-Handler")
}
