// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"errors"
	"log/slog"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

type knownFQDN struct {
	name string
	log  *slog.Logger
}

func NewKnownFQDN() et.Plugin {
	return &knownFQDN{
		name: "Known-FQDN",
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
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	d.process(e, d.lookup(e, e.Entity))
	return nil
}

func (d *knownFQDN) lookup(e *et.Event, dom *dbt.Entity) []*dbt.Entity {
	names, _ := utils.FindByFQDNScope(e.Session.Cache(), dom, time.Time{})
	return names
}

func (d *knownFQDN) process(e *et.Event, names []*dbt.Entity) {
	for _, n := range names {
		if fqdn, ok := n.Asset.(*oamdns.FQDN); ok {
			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    fqdn.Name,
				Entity:  n,
				Session: e.Session,
			})
		}
	}
}
