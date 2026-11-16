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

// columbus discovers subdomains from the Columbus Project
// (columbus.elmasy.com), a free, key-less subdomain index. Its lookup returns
// the subdomain labels of a domain as a JSON string array.
type columbus struct {
	name   string
	url    string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewColumbus() et.Plugin {
	return &columbus{
		name:   "Columbus",
		url:    "https://columbus.elmasy.com/lookup/",
		rlimit: rate.NewLimiter(rate.Every(5*time.Second), 1),
		source: &et.Source{
			Name:       "Columbus",
			Confidence: 80,
		},
	}
}

func (c *columbus) Name() string {
	return c.name
}

func (c *columbus) Start(r et.Registry) error {
	c.log = r.Log().WithGroup("plugin").With("name", c.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       c,
		Name:         c.name + "-Handler",
		Position:     38,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     c.check,
	}); err != nil {
		return err
	}

	c.log.Info("Plugin started")
	return nil
}

func (c *columbus) Stop() {
	c.log.Info("Plugin stopped")
}

func (c *columbus) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), c.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, c.source, since) {
		names = append(names, c.query(e, fqdn.Name)...)
		support.MarkAssetMonitored(e.Session, e.Entity, c.source)
	}

	if len(names) > 0 {
		c.process(e, names)
	}
	return nil
}

func (c *columbus) query(e *et.Event, name string) []*dbt.Entity {
	return c.store(e, c.collect(e, name))
}

// collect looks up name and returns the in-scope subdomains the service
// reports, deduplicated.
func (c *columbus) collect(e *et.Event, name string) []string {
	body, ok := c.fetch(e, name)
	if !ok {
		return nil
	}

	seen := make(map[string]struct{})
	var names []string
	for _, n := range parseColumbus([]byte(body), name) {
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

func (c *columbus) fetch(e *et.Event, domain string) (string, bool) {
	if err := support.WaitLimit(e.Session.Ctx(), c.rlimit); err != nil {
		return "", false
	}

	e.Session.NetSem().Acquire()
	defer e.Session.NetSem().Release()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General,
		&amasshttp.Request{URL: c.url + domain})
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK || resp.Body == "" {
		return "", false
	}

	return resp.Body, true
}

// parseColumbus turns the service's array of subdomain labels into full names
// under domain. An empty label is the domain itself.
func parseColumbus(body []byte, domain string) []string {
	var labels []string
	if err := json.Unmarshal(body, &labels); err != nil {
		return nil
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	var names []string
	for _, label := range labels {
		label = strings.ToLower(strings.Trim(strings.TrimSpace(label), "."))
		name := domain
		if label != "" {
			name = label + "." + domain
		}
		if name != "" {
			names = append(names, name)
		}
	}

	return names
}

func (c *columbus) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, c.source, c.name, c.name+"-Handler")
}

func (c *columbus) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, c.source)
}
