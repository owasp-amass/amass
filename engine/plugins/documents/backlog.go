// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"context"
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// backlog hands the pipeline again the documents an in-scope host serves
// that earlier runs left unread: URLs of the host (URL --domain--> FQDN) with
// a document's extension, no File stored, and no attempt within the URL->File
// ttl in the config. They were left past a run's limit, or because a
// document named them, and nothing else might name them again. At most
// max_per_run are handed over, the most the run can fetch for the domain.
func (d *documents) backlog(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok || !inScope(e, fqdn.Name) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.URL), d.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, d.source, since) {
		return nil
	}
	support.MarkAssetMonitored(e.Session, e.Entity, d.source)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 2*time.Minute)
	defer cancel()

	edges, err := e.Session.DB().IncomingEdges(ctx, e.Entity, time.Time{}, "domain")
	if err != nil {
		return nil
	}

	rules := semantics.Documents()
	refetch, err := support.TTLStartTime(e.Session.Config(), string(oam.URL), string(oam.File), d.name)
	if err != nil {
		return err
	}
	var handed int
	for _, edge := range edges {
		if handed >= rules.MaxPerRun || ctx.Err() != nil {
			break
		}

		ent, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID)
		if err != nil || ent == nil {
			continue
		}
		u, ok := ent.Asset.(*oamurl.URL)
		if !ok {
			continue
		}
		if _, isDoc := rules.DocumentFor(u.Path); !isDoc {
			continue
		}
		if storedSince(e, ent, time.Time{}) || d.attemptedSince(e, ent, refetch) {
			continue
		}

		handed++
		d.dispatch(e, ent, u.Raw)
	}

	if handed > 0 {
		e.Session.Log().Info("documents left by earlier runs handed back", "host", fqdn.Name, "count", handed,
			slog.Group("plugin", "name", d.name, "handler", d.name+"-Backlog-Handler"))
	}
	return nil
}
