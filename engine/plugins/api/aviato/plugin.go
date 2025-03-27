// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aviato

import (
	"errors"
	"time"

	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"golang.org/x/time/rate"
)

func NewAviato() et.Plugin {
	limit := rate.Every(time.Second)

	return &aviato{
		name:   "Aviato",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "Aviato",
			Confidence: 90,
		},
	}
}

func (a *aviato) Name() string {
	return a.name
}

func (a *aviato) Start(r et.Registry) error {
	a.log = r.Log().WithGroup("plugin").With("name", a.name)

	a.companySearch = &companySearch{
		name:   a.name + "-Company-Search-Handler",
		plugin: a,
	}

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     a,
		Name:       a.companySearch.name,
		Priority:   6,
		Transforms: []string{string(oam.Identifier)},
		EventType:  oam.Organization,
		Callback:   a.companySearch.check,
	}); err != nil {
		return err
	}

	a.log.Info("Plugin started")
	return nil
}

func (a *aviato) Stop() {
	a.log.Info("Plugin stopped")
}

func (a *aviato) createRelation(session et.Session, obj *dbt.Entity, rel oam.Relation, subject *dbt.Entity, conf int) error {
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
		Source:     a.source.Name,
		Confidence: conf,
	})
	return err
}
