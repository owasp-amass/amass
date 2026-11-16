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
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

// certSpotterMaxPages bounds how far the issuance list is paged for one name.
// CertSpotter returns up to 100 issuances a page, oldest first.
const certSpotterMaxPages = 20

// certSpotter discovers subdomains from the Certificate Transparency logs
// through SSLMate's CertSpotter API, a reliable, key-optional alternative to
// crt.sh. Only the subject names of logged certificates are read.
type certSpotter struct {
	name   string
	url    string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewCertSpotter() et.Plugin {
	return &certSpotter{
		name:   "CertSpotter",
		url:    "https://api.certspotter.com/v1/issuances",
		rlimit: rate.NewLimiter(rate.Every(5*time.Second), 1),
		source: &et.Source{
			Name:       "CertSpotter",
			Confidence: 100,
		},
	}
}

func (c *certSpotter) Name() string {
	return c.name
}

func (c *certSpotter) Start(r et.Registry) error {
	c.log = r.Log().WithGroup("plugin").With("name", c.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       c,
		Name:         c.name + "-Handler",
		Position:     26,
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

func (c *certSpotter) Stop() {
	c.log.Info("Plugin stopped")
}

func (c *certSpotter) check(e *et.Event) error {
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

func (c *certSpotter) query(e *et.Event, name string) []*dbt.Entity {
	return c.store(e, c.collect(e, name))
}

// collect pages through the issuances for name within the plugin's bounds and
// returns the in-scope names found, deduplicated. It stops at the first page
// that is not served, does not advance the cursor, or adds no new name.
func (c *certSpotter) collect(e *et.Event, name string) []string {
	seen := make(map[string]struct{})
	var names []string

	after := ""
	for page := 0; page < certSpotterMaxPages; page++ {
		body, ok := c.fetch(e, name, after)
		if !ok {
			break
		}

		dnsNames, last := parseCertSpotter([]byte(body))
		added := false
		for _, n := range dnsNames {
			n = strings.ToLower(strings.TrimSpace(amassdns.RemoveAsteriskLabel(n)))
			if n == "" {
				continue
			}
			if _, dup := seen[n]; dup {
				continue
			}

			seen[n] = struct{}{}
			added = true
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: n}, 0); conf > 0 {
				names = append(names, n)
			}
		}
		if last == "" || last == after || !added {
			break
		}

		after = last
	}

	return names
}

func (c *certSpotter) fetch(e *et.Event, domain, after string) (string, bool) {
	if err := support.WaitLimit(e.Session.Ctx(), c.rlimit); err != nil {
		return "", false
	}

	e.Session.NetSem().Acquire()
	defer e.Session.NetSem().Release()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	u := c.url + "?domain=" + url.QueryEscape(domain) + "&include_subdomains=true&expand=dns_names"
	if after != "" {
		u += "&after=" + url.QueryEscape(after)
	}

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: u})
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK || resp.Body == "" {
		return "", false
	}

	return resp.Body, true
}

// parseCertSpotter returns the DNS names across an issuances response and the
// id of the last issuance, which pages the next request.
func parseCertSpotter(body []byte) ([]string, string) {
	var issuances []struct {
		ID       string   `json:"id"`
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &issuances); err != nil {
		return nil, ""
	}

	var names []string
	last := ""
	for _, is := range issuances {
		names = append(names, is.DNSNames...)
		if is.ID != "" {
			last = is.ID
		}
	}

	return names, last
}

func (c *certSpotter) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, c.source, c.name, c.name+"-Handler")
}

func (c *certSpotter) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, c.source)
}
