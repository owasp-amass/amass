// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"errors"
	"log/slog"
	"strings"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
)

type knownFQDN struct {
	name string
	log  *slog.Logger
	rels []string
}

func NewKnownFQDN() et.Plugin {
	return &knownFQDN{
		name: "Known-FQDN",
		rels: []string{"a_record", "aaaa_record", "cname_record", "ns_record", "mx_record", "srv_record", "node"},
	}
}

func (d *knownFQDN) Name() string {
	return d.name
}

func (d *knownFQDN) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.name + "-Handler",
		Priority:     7,
		MaxInstances: 10,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     d.check,
	}); err != nil {
		return err
	}

	d.log.Info("Plugin started")
	return nil
}

func (d *knownFQDN) Stop() {
	d.log.Info("Plugin stopped")
}

func (d *knownFQDN) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	assets := d.lookup(e, fqdn)
	if len(assets) == 0 {
		e.Session.Log().Error("Failed to query the asset database",
			slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
		return nil
	}

	d.process(e, assets)
	return nil
}

func (d *knownFQDN) lookup(e *et.Event, dom *domain.FQDN) []*dbt.Asset {
	var assets []*dbt.Asset

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		names, err := e.Session.DB().FindByScope([]oam.Asset{dom}, time.Time{})
		if err != nil || len(names) == 0 {
			return
		}

		for _, name := range names {
			if rels, err := e.Session.DB().OutgoingRelations(name, time.Time{}, d.rels...); err == nil && len(rels) > 0 {
				assets = append(assets, name)
			}
		}
	})
	<-done
	close(done)
	return assets
}

func (d *knownFQDN) process(e *et.Event, assets []*dbt.Asset) {
	for _, a := range assets {
		if fqdn, ok := a.Asset.(*domain.FQDN); ok {
			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    fqdn.Name,
				Asset:   a,
				Session: e.Session,
			})
		}
	}
}
