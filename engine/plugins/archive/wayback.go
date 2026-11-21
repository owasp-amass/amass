// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

// wayback asks the Wayback Machine's CDX server for the URLs it captured
// under a domain.
type wayback struct {
	name   string
	URL    string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewWayback() et.Plugin {
	limit := rate.Every(10 * time.Second)

	return &wayback{
		name: "Wayback",
		// One row per distinct URL (collapse=urlkey) with the timestamp of its
		// first capture.
		URL:    "https://web.archive.org/cdx/search/cdx?matchType=domain&fl=original,timestamp&output=json&collapse=urlkey&url=",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "Wayback",
			Confidence: 80,
		},
	}
}

func (w *wayback) Name() string {
	return w.name
}

func (w *wayback) Start(r et.Registry) error {
	w.log = r.Log().WithGroup("plugin").With("name", w.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       w,
		Name:         w.name + "-Handler",
		Position:     40,
		MaxInstances: 1,
		Transforms:   []string{string(oam.FQDN), string(oam.URL)},
		EventType:    oam.FQDN,
		Callback:     w.check,
	}); err != nil {
		return err
	}

	w.log.Info("Plugin started")
	return nil
}

func (w *wayback) Stop() {
	w.log.Info("Plugin stopped")
}

func (w *wayback) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) || !queryRoot(e.Session, fqdn.Name) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), w.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, w.source, since) {
		return nil
	}

	rows := w.query(e, fqdn.Name)
	support.MarkAssetMonitored(e.Session, e.Entity, w.source)

	names, urls := harvest(e, w.source, w.name, rows)
	if len(names) > 0 {
		support.ProcessFQDNsWithSource(e, names, w.source)
	}
	if len(urls) > 0 {
		storeURLs(e, w.source, w.name, urls)
	}
	return nil
}

// query returns the captures the Wayback Machine holds under the domain, or
// none when it refuses or fails.
func (w *wayback) query(e *et.Event, name string) []archiveRow {
	_ = support.WaitLimit(e.Session.Ctx(), w.rlimit)
	e.Session.NetSem().Acquire()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 60*time.Second)
	defer cancel()

	end := fmt.Sprintf("*.%s/*", name)
	resp, err := amasshttp.RequestWebPage(ctx,
		e.Session.Clients().General, &amasshttp.Request{URL: w.URL + end})
	e.Session.NetSem().Release()
	// a refusal or rate limit is not read as an answer
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return nil
	}

	var raw [][]string
	if err := json.Unmarshal([]byte(resp.Body), &raw); err != nil {
		return nil
	}

	rows := make([]archiveRow, 0, len(raw))
	for _, r := range raw {
		switch len(r) {
		case 1:
			rows = append(rows, archiveRow{raw: r[0]})
		case 2:
			rows = append(rows, archiveRow{raw: r[0], timestamp: r[1]})
		}
	}

	return rows
}
