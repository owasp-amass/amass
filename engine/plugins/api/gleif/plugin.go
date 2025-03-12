// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"errors"
	"time"

	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"golang.org/x/time/rate"
)

func NewGLEIF() et.Plugin {
	limit := rate.Every(3 * time.Second)

	return &gleif{
		name:   "GLEIF",
		rlimit: rate.NewLimiter(limit, 1),
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
		Priority:     6,
		MaxInstances: 1,
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
		Priority:     6,
		MaxInstances: 1,
		Transforms:   []string{string(oam.Organization)},
		EventType:    oam.Identifier,
		Callback:     g.related.check,
	}); err != nil {
		return err
	}

	g.log.Info("Plugin started")
	return nil
}

func (g *gleif) Stop() {
	g.log.Info("Plugin stopped")
}

func (g *gleif) createRelation(session et.Session, obj *dbt.Entity, rel oam.Relation, subject *dbt.Entity, conf int) error {
	edge, err := session.Cache().CreateEdge(&dbt.Edge{
		Relation:   rel,
		FromEntity: obj,
		ToEntity:   subject,
	})
	if err != nil {
		return err
	} else if edge == nil {
		return errors.New("failed to create the edge")
	}

	_, err = session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
		Source:     g.source.Name,
		Confidence: conf,
	})
	return err
}
