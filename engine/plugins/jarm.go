// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/platform"
)

type jarmPlugin struct {
	name   string
	log    *slog.Logger
	source *et.Source
}

func NewJARMFingerprints() et.Plugin {
	return &jarmPlugin{
		name: "JARM-Fingerprint",
		source: &et.Source{
			Name:       "JARM-Fingerprint",
			Confidence: 90,
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
		Position:     42,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.Service)},
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
	_, ok := e.Entity.Asset.(*platform.Service)
	if !ok {
		return errors.New("failed to extract the Service asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Service), string(oam.Service), j.name)
	if err != nil {
		return err
	}

	if !j.hasCertificate(e, since) {
		return nil
	}

	src := j.source
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		j.query(e, since)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}
	return nil
}

func (j *jarmPlugin) hasCertificate(e *et.Event, since time.Time) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if edges, err := e.Session.DB().OutgoingEdges(ctx, e.Entity, since, "certificate"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if a.Asset.AssetType() == oam.TLSCertificate {
					return true
				}
			}
		}
	}
	return false
}

type fingerprint struct {
	asset *dbt.Entity
	port  *dbt.Edge
	hash  string
}

func (j *jarmPlugin) query(e *et.Event, since time.Time) {
	var targets []*fingerprint

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if edges, err := e.Session.DB().IncomingEdges(ctx, e.Entity, since); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			portrel, ok := edge.Relation.(*general.PortRelation)
			if !ok {
				continue
			}
			if a, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
				switch a.Asset.(type) {
				case *oamdns.FQDN:
					if portrel.Protocol == "TCP" {
						t := &fingerprint{
							asset: e.Entity,
							port:  edge,
						}
						targets = append([]*fingerprint{t}, targets...)
					}
				case *network.IPAddress:
					if portrel.Protocol == "TCP" {
						targets = append(targets, &fingerprint{
							asset: e.Entity,
							port:  edge,
						})
					}
				}
			}
		}
	}

	var results []*fingerprint
	for _, target := range targets {
		portrel := target.port.Relation.(*general.PortRelation)
		if fp, err := support.JARMFingerprint(target.asset.Asset, portrel); err == nil && fp != "" {
			results = append(results, &fingerprint{
				asset: target.asset,
				port:  target.port,
				hash:  fp,
			})
		}
	}

	if len(results) > 0 {
		j.store(e, results)
	}
}

func (j *jarmPlugin) store(e *et.Event, fps []*fingerprint) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, fp := range fps {
		_, _ = e.Session.DB().CreateEdgeProperty(ctx, fp.port, &general.SimpleProperty{
			PropertyName:  "JARM",
			PropertyValue: fp.hash,
		})
	}
}
