// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
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
	_, ok := e.Entity.Asset.(*oamplat.Service)
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
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 3*time.Second)
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

// maxJARMTargets bounds the hosts probed for one service; each target
// costs ten TLS connections.
const maxJARMTargets = 4

func (j *jarmPlugin) query(e *et.Event, since time.Time) {
	var targets []*fingerprint

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := e.Session.DB().IncomingEdges(ctx, e.Entity, since); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
				if t := jarmTarget(a, edge); t != nil {
					if _, isName := a.Asset.(*oamdns.FQDN); isName {
						// Names first: the probes then carry the server name.
						targets = append([]*fingerprint{t}, targets...)
					} else {
						targets = append(targets, t)
					}
				}
			}
		}
	}
	if len(targets) > maxJARMTargets {
		targets = targets[:maxJARMTargets]
	}

	var results []*fingerprint
	for _, target := range targets {
		portrel := target.port.Relation.(*oamgen.PortRelation)
		if fp, err := support.JARMFingerprint(e.Session, target.asset.Asset, portrel); err == nil && fp != "" {
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

// jarmTarget returns the host behind a TCP port relation to a service as a
// fingerprint target, or nil. The target is the host (an FQDN or IP
// address), which is what the probes connect to, not the service.
func jarmTarget(host *dbt.Entity, edge *dbt.Edge) *fingerprint {
	portrel, ok := edge.Relation.(*oamgen.PortRelation)
	if !ok || !strings.EqualFold(portrel.Protocol, "tcp") || host == nil || host.Asset == nil {
		return nil
	}

	switch host.Asset.(type) {
	case *oamdns.FQDN, *oamnet.IPAddress:
		return &fingerprint{asset: host, port: edge}
	}

	return nil
}

func (j *jarmPlugin) store(e *et.Event, fps []*fingerprint) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 5*time.Second)
	defer cancel()

	for _, fp := range fps {
		_, _ = e.Session.DB().CreateEdgeProperty(ctx, fp.port, &oamgen.SimpleProperty{
			PropertyName:  "JARM",
			PropertyValue: fp.hash,
		})
	}
}
