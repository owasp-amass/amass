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
	"net/url"
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

// threatMiner discovers subdomains from ThreatMiner (api.threatminer.org), a
// free, key-less threat-intelligence service. Report type 5 of its domain
// endpoint returns the known subdomains of a domain.
type threatMiner struct {
	name   string
	url    string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewThreatMiner() et.Plugin {
	return &threatMiner{
		name: "ThreatMiner",
		url:  "https://api.threatminer.org/v2/domain.php",
		// ThreatMiner allows ten queries a minute.
		rlimit: rate.NewLimiter(rate.Every(6*time.Second), 1),
		source: &et.Source{
			Name:       "ThreatMiner",
			Confidence: 60,
		},
	}
}

func (t *threatMiner) Name() string {
	return t.name
}

func (t *threatMiner) Start(r et.Registry) error {
	t.log = r.Log().WithGroup("plugin").With("name", t.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       t,
		Name:         t.name + "-Handler",
		Position:     40,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     t.check,
	}); err != nil {
		return err
	}

	t.log.Info("Plugin started")
	return nil
}

func (t *threatMiner) Stop() {
	t.log.Info("Plugin stopped")
}

func (t *threatMiner) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), t.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, t.source, since) {
		names = append(names, t.query(e, fqdn.Name)...)
		support.MarkAssetMonitored(e.Session, e.Entity, t.source)
	}

	if len(names) > 0 {
		t.process(e, names)
	}
	return nil
}

func (t *threatMiner) query(e *et.Event, name string) []*dbt.Entity {
	return t.store(e, t.collect(e, name))
}

func (t *threatMiner) collect(e *et.Event, name string) []string {
	body, ok := t.fetch(e, name)
	if !ok {
		return nil
	}

	seen := make(map[string]struct{})
	var names []string
	for _, n := range parseThreatMiner([]byte(body)) {
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

func (t *threatMiner) fetch(e *et.Event, domain string) (string, bool) {
	if err := support.WaitLimit(e.Session.Ctx(), t.rlimit); err != nil {
		return "", false
	}

	e.Session.NetSem().Acquire()
	defer e.Session.NetSem().Release()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	// Report type 5 is the domain's subdomains.
	u := t.url + "?q=" + url.QueryEscape(domain) + "&rt=5"
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: u})
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK || resp.Body == "" {
		return "", false
	}

	return resp.Body, true
}

// parseThreatMiner returns the subdomains in a report-type-5 response. The
// results field is an array of subdomain names; a response without one (for
// example a 404 "no results" body) yields nothing.
func parseThreatMiner(body []byte) []string {
	var out struct {
		Results []string `json:"results"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil
	}

	var names []string
	for _, n := range out.Results {
		n = strings.ToLower(strings.Trim(strings.TrimSpace(n), "."))
		if n != "" {
			names = append(names, n)
		}
	}

	return names
}

func (t *threatMiner) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, t.source, t.name, t.name+"-Handler")
}

func (t *threatMiner) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, t.source)
}
