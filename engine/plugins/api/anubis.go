// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

// anubis discovers subdomains from Anubis-DB (anubisdb.com), a free, key-less
// subdomain index whose lookup returns a JSON array of full subdomain names.
type anubis struct {
	name   string
	url    string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewAnubis() et.Plugin {
	return &anubis{
		name:   "Anubis",
		url:    "https://anubisdb.com/anubis/subdomains/",
		rlimit: rate.NewLimiter(rate.Every(2*time.Second), 1),
		source: &et.Source{
			Name:       "Anubis",
			Confidence: 70,
		},
	}
}

func (a *anubis) Name() string {
	return a.name
}

func (a *anubis) Start(r et.Registry) error {
	a.log = r.Log().WithGroup("plugin").With("name", a.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       a,
		Name:         a.name + "-Handler",
		Position:     39,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     a.check,
	}); err != nil {
		return err
	}

	a.log.Info("Plugin started")
	return nil
}

func (a *anubis) Stop() {
	a.log.Info("Plugin stopped")
}

func (a *anubis) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), a.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, a.source, since) {
		names = append(names, a.query(e, fqdn.Name)...)
		support.MarkAssetMonitored(e.Session, e.Entity, a.source)
	}

	if len(names) > 0 {
		a.process(e, names)
	}
	return nil
}

func (a *anubis) query(e *et.Event, name string) []*dbt.Entity {
	return a.store(e, a.collect(e, name))
}

func (a *anubis) collect(e *et.Event, name string) []string {
	body, ok := a.fetch(e, name)
	if !ok {
		return nil
	}

	seen := make(map[string]struct{})
	var names []string
	for _, n := range parseAnubis([]byte(body)) {
		if _, dup := seen[n]; dup {
			continue
		}

		seen[n] = struct{}{}
		if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: n}, 0); conf > 0 {
			names = append(names, n)
		}
	}

	return names
}

func (a *anubis) fetch(e *et.Event, domain string) (string, bool) {
	if err := support.WaitLimit(e.Session.Ctx(), a.rlimit); err != nil {
		return "", false
	}

	e.Session.NetSem().Acquire()
	defer e.Session.NetSem().Release()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General,
		&amasshttp.Request{URL: a.url + domain})
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK || resp.Body == "" {
		return "", false
	}

	return resp.Body, true
}

// parseAnubis turns the service's array of full subdomain names into a cleaned
// list of lower-case names.
func parseAnubis(body []byte) []string {
	var found []string
	if err := json.Unmarshal(body, &found); err != nil {
		return nil
	}

	var names []string
	for _, n := range found {
		n = strings.ToLower(strings.Trim(strings.TrimSpace(n), "."))
		if n != "" {
			names = append(names, n)
		}
	}

	return names
}

func (a *anubis) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, a.source, a.name, a.name+"-Handler")
}

func (a *anubis) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, a.source)
}
