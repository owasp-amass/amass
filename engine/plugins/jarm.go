// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"errors"
	"log/slog"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/fingerprint"
	"github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/service"
	"github.com/owasp-amass/open-asset-model/source"
)

type jarmPlugin struct {
	name   string
	log    *slog.Logger
	source *source.Source
}

func NewJARMFingerprint() et.Plugin {
	return &jarmPlugin{
		name: "JARM-Fingerprint",
		source: &source.Source{
			Name:       "JARM-Fingerprint",
			Confidence: 100,
		},
	}
}

func (j *jarmPlugin) Name() string {
	return j.name
}

func (j *jarmPlugin) Start(r et.Registry) error {
	j.log = r.Log().WithGroup("plugin").With("name", j.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       j,
		Name:         j.name + "-Handler",
		MaxInstances: 25,
		Transforms:   []string{string(oam.Fingerprint)},
		EventType:    oam.Service,
		Callback:     j.check,
	}); err != nil {
		return err
	}

	j.log.Info("Plugin started")
	return nil
}

func (j *jarmPlugin) Stop() {
	j.log.Info("Plugin stopped")
}

func (j *jarmPlugin) check(e *et.Event) error {
	_, ok := e.Asset.Asset.(*service.Service)
	if !ok {
		return errors.New("failed to extract the Service asset")
	}

	if !j.hasCertificate(e) {
		return nil
	}

	src := support.GetSource(e.Session, j.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Service), string(oam.Fingerprint), j.name)
	if err != nil {
		return err
	}

	var findings []*support.Finding
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		findings = append(findings, j.lookup(e, e.Asset, since)...)
	} else {
		findings = append(findings, j.query(e, e.Asset, src)...)
		support.MarkAssetMonitored(e.Session, e.Asset, src)
	}

	if len(findings) > 0 {
		j.process(e, findings, src)
	}
	return nil
}

func (j *jarmPlugin) hasCertificate(e *et.Event) bool {
	if relations, hit := e.Session.Cache().GetRelations(&dbt.Relation{
		FromAsset: e.Asset,
		Type:      "certificate",
	}); hit && len(relations) > 0 {
		for _, relation := range relations {
			if a := relation.ToAsset.Asset; a.AssetType() == oam.TLSCertificate {
				return true
			}
		}
	}
	return false
}

func (j *jarmPlugin) lookup(e *et.Event, asset *dbt.Asset, since time.Time) []*support.Finding {
	var findings []*support.Finding
	serv := asset.Asset.(*service.Service)

	if rels, err := e.Session.DB().OutgoingRelations(asset, since, "fingerprint"); err == nil && len(rels) > 0 {
		for _, rel := range rels {
			if a, err := e.Session.DB().FindById(rel.ToAsset.ID, since); err == nil && a != nil {
				if pr, ok := a.Asset.(*fingerprint.Fingerprint); ok && pr.Type == "JARM" {
					findings = append(findings, &support.Finding{
						From:     asset,
						FromName: "Service:" + serv.Identifier,
						To:       a,
						ToName:   "JARM: " + pr.Value,
						Rel:      "fingerprint",
					})
					break
				}
			}
		}
	}
	return findings
}

func (j *jarmPlugin) query(e *et.Event, asset, src *dbt.Asset) []*support.Finding {
	var targets []oam.Asset

	if relations, hit := e.Session.Cache().GetRelations(&dbt.Relation{
		ToAsset: asset,
		Type:    "service",
	}); hit && len(relations) > 0 {
		for _, relation := range relations {
			switch v := relation.FromAsset.Asset.(type) {
			case *domain.NetworkEndpoint:
				if v.Protocol == "https" {
					targets = append([]oam.Asset{v}, targets...)
				}
			case *network.SocketAddress:
				if v.Protocol == "https" {
					targets = append(targets, v)
				}
			}
		}
	}

	var findings []*support.Finding
	for _, target := range targets {
		if fp, err := support.JARMFingerprint(target); err == nil && fp != "" {
			findings = append(findings, j.store(e, fp, asset, src)...)
			break
		}
	}
	return findings
}

func (j *jarmPlugin) store(e *et.Event, fp string, asset, src *dbt.Asset) []*support.Finding {
	var findings []*support.Finding
	serv := asset.Asset.(*service.Service)

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		if a, err := e.Session.DB().Create(asset, "fingerprint", &fingerprint.Fingerprint{
			Value: fp,
			Type:  "JARM",
		}); err == nil && a != nil {
			_, _ = e.Session.DB().Link(a, "source", src)
			findings = append(findings, &support.Finding{
				From:     asset,
				FromName: "Service:" + serv.Identifier,
				To:       a,
				ToName:   "JARM: " + fp,
				Rel:      "fingerprint",
			})
		}
	})
	<-done
	close(done)
	return findings
}

func (j *jarmPlugin) process(e *et.Event, findings []*support.Finding, src *dbt.Asset) {
	support.ProcessAssetsWithSource(e, findings, src, j.name, j.name+"-Handler")
}
