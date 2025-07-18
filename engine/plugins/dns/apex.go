// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"errors"
	"log/slog"
	"strings"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
)

type dnsApex struct {
	name   string
	plugin *dnsPlugin
}

func (d *dnsApex) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if e.Meta == nil {
		return nil
	} else if m, ok := e.Meta.(*support.FQDNMeta); !ok || len(m.RecordTypes) == 0 {
		return nil
	}

	// determine which domain apex is the parent of this name
	var name string
	best := len(fqdn.Name)
	for _, n := range d.plugin.getApexList() {
		if idx := strings.Index(fqdn.Name, n); idx != -1 && idx != 0 && idx < best {
			best = idx
			name = n
		}
	}
	if name == "" {
		return nil
	}

	if apex := d.plugin.getApex(name); apex != nil && apex.Asset.Key() != fqdn.Name {
		d.store(e, fqdn.Name, e.Entity, apex)
	}
	return nil
}

func (d *dnsApex) store(e *et.Event, name string, fqdn, apex *dbt.Entity) {
	if _, err := e.Session.Cache().CreateEdge(&dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "node"},
		FromEntity: apex,
		ToEntity:   fqdn,
	}); err == nil {
		e.Session.Log().Info("relationship discovered", "from", apex.Asset.Key(), "relation",
			"node", "to", name, slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
	}
}
