// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"log/slog"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type gleif struct {
	name    string
	log     *slog.Logger
	fuzzy   *fuzzyCompletions
	related *relatedOrgs
	address *addresses
	source  *et.Source
}

func NewGLEIF() et.Plugin {
	return &gleif{
		name: "GLEIF",
		source: &et.Source{
			Name:       "GLEIF",
			Confidence: 100,
		},
	}
}

func (g *gleif) Name() string {
	return g.name
}

func (g *gleif) Start(r et.Registry) error {
	g.log = r.Log().WithGroup("plugin").With("name", g.name)

	g.fuzzy = &fuzzyCompletions{
		name:   g.name + "-Fuzzy-Handler",
		plugin: g,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       g,
		Name:         g.fuzzy.name,
		Position:     48,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Identifier)},
		EventType:    oam.Organization,
		Callback:     g.fuzzy.check,
	}); err != nil {
		return err
	}

	g.related = &relatedOrgs{
		name:   g.name + "-LEI-Handler",
		plugin: g,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       g,
		Name:         g.related.name,
		Position:     48,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Organization)},
		EventType:    oam.Identifier,
		Callback:     g.related.check,
	}); err != nil {
		return err
	}

	// The reverse direction: from a street address to the organizations
	// registered there, so an enumeration can pivot from a StreetAddress seed.
	g.address = &addresses{
		name:   g.name + "-Address-Handler",
		plugin: g,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       g,
		Name:         g.address.name,
		Position:     48,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Organization), string(oam.ContactRecord), string(oam.Identifier)},
		EventType:    oam.StreetAddress,
		Callback:     g.address.check,
	}); err != nil {
		return err
	}

	g.log.Info("Plugin started")
	return nil
}

func (g *gleif) Stop() {
	g.log.Info("Plugin stopped")
}

// withConfidence is the plugin's source at the confidence of one finding.
func (g *gleif) withConfidence(conf int) *et.Source {
	return &et.Source{Name: g.source.Name, Confidence: conf}
}
