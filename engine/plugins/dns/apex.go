// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"errors"
	"log/slog"
	"strings"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/domain"
)

type dnsApex struct {
	name   string
	plugin *dnsPlugin
}

func (d *dnsApex) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.NameResolved(e.Session, fqdn) {
		return nil
	}

	rels, hit := e.Session.Cache().GetRelationsByType("ns_record")
	if !hit || len(rels) == 0 {
		return nil
	}

	var apexes []*dbt.Asset
	for _, r := range rels {
		apexes = append(apexes, r.FromAsset)
	}

	// determine which domain apex this name is a node in
	var apex *dbt.Asset
	best := len(fqdn.Name)
	for _, a := range apexes {
		n, ok := a.Asset.(*domain.FQDN)
		if !ok {
			continue
		}
		if idx := strings.Index(fqdn.Name, n.Name); idx != -1 && idx != 0 && idx < best {
			best = idx
			apex = a
		}
	}

	if apex != nil {
		d.store(e, fqdn.Name, e.Asset, apex)
	}
	return nil
}

func (d *dnsApex) store(e *et.Event, name string, fqdn, apex *dbt.Asset) {
	done := make(chan struct{}, 1)
	defer close(done)

	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}
		if _, err := e.Session.DB().Link(apex, "node", fqdn); err == nil {
			e.Session.Log().Info("relationship discovered", "from", apex.Asset.Key(), "relation",
				"node", "to", name, slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		}
	})
	<-done
}
