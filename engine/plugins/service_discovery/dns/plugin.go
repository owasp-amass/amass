// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type dnsPlugin struct {
	name   string
	log    *slog.Logger
	source *et.Source
	txt    *txtHandler
}

func NewDNSPlugin() et.Plugin {
	return &dnsPlugin{
		name: "DNS-SD",
		source: &et.Source{
			Name:       "DNS-Service-Discovery",
			Confidence: 100,
		},
	}
}

func (p *dnsPlugin) Name() string {
	return p.name
}

func (p *dnsPlugin) Start(r et.Registry) error {
	p.log = r.Log().WithGroup("plugin").With("name", p.name)

	p.txt = &txtHandler{
		name:   p.name + "-TXT-Handler",
		source: p.source,
		plugin: p,
	}

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     p,
		Name:       p.txt.name,
		Priority:   9,
		Transforms: []string{string(oam.FQDN)},
		EventType:  oam.FQDN,
		Callback:   p.txt.check,
	}); err != nil {
		p.log.Error("failed to register handler", "error", err)
		return err
	}

	p.log.Info("plugin started")
	return nil
}

func (p *dnsPlugin) Stop() {
	p.log.Info("plugin stopped")
}
