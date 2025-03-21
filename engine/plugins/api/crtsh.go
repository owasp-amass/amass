// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/dns"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type crtsh struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewCrtsh() et.Plugin {
	limit := rate.Every(2 * time.Second)

	return &crtsh{
		name:   "crt.sh",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "HackerTarget",
			Confidence: 100,
		},
	}
}

func (c *crtsh) Name() string {
	return c.name
}

func (c *crtsh) Start(r et.Registry) error {
	c.log = r.Log().WithGroup("plugin").With("name", c.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       c,
		Name:         c.name + "-Handler",
		Priority:     5,
		MaxInstances: 10,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     c.check,
	}); err != nil {
		return err
	}

	c.log.Info("Plugin started")
	return nil
}

func (c *crtsh) Stop() {
	c.log.Info("Plugin stopped")
}

func (c *crtsh) check(e *et.Event) error {
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
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, c.source, since) {
		names = append(names, c.lookup(e, fqdn.Name, since)...)
	} else {
		names = append(names, c.query(e, fqdn.Name)...)
		support.MarkAssetMonitored(e.Session, e.Entity, c.source)
	}

	if len(names) > 0 {
		c.process(e, names)
	}
	return nil
}

func (c *crtsh) lookup(e *et.Event, name string, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), c.source, since)
}

func (c *crtsh) query(e *et.Event, name string) []*dbt.Entity {
	_ = c.rlimit.Wait(context.TODO())
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		URL: "https://crt.sh/?CN=" + name + "&output=json&exclude=expired",
	})
	if err != nil {
		return nil
	}

	var result struct {
		Certs []struct {
			Names string `json:"name_value"`
		} `json:"certs"`
	}
	if err := json.Unmarshal([]byte("{\"certs\":"+resp.Body+"}"), &result); err != nil {
		return nil
	}

	var names []string
	for _, cert := range result.Certs {
		for _, n := range strings.Split(cert.Names, "\n") {
			nstr := strings.ToLower(strings.TrimSpace(dns.RemoveAsteriskLabel(n)))
			// if the subdomain is not in scope, skip it
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: nstr}, 0); conf > 0 {
				names = append(names, nstr)
			}
		}
	}

	return c.store(e, names)
}

func (c *crtsh) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, c.source, c.name, c.name+"-Handler")
}

func (c *crtsh) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, c.source)
}
