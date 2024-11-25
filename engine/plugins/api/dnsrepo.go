// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"go.uber.org/ratelimit"
)

type dnsrepo struct {
	name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
	source *et.Source
}

func NewDNSRepo() et.Plugin {
	return &dnsrepo{
		name:   "DNSRepo",
		rlimit: ratelimit.New(10, ratelimit.WithoutSlack),
		source: &et.Source{
			Name:       "DNSRepo",
			Confidence: 80,
		},
	}
}

func (d *dnsrepo) Name() string {
	return d.name
}

func (d *dnsrepo) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.name + "-Handler",
		Priority:     5,
		MaxInstances: 10,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     d.check,
	}); err != nil {
		return err
	}

	d.log.Info("Plugin started")
	return nil
}

func (d *dnsrepo) Stop() {
	d.log.Info("Plugin stopped")
}

func (d *dnsrepo) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	var keys []string
	ds := e.Session.Config().GetDataSourceConfig(d.name)
	if ds != nil {
		for _, cred := range ds.Creds {
			keys = append(keys, cred.Apikey)
		}
	}
	// add an empty API key
	keys = append(keys, "")

	if a, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 || a == nil {
		return nil
	} else if f, ok := a.(*domain.FQDN); !ok || f == nil || !strings.EqualFold(fqdn.Name, f.Name) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), d.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, d.source, since) {
		names = append(names, d.lookup(e, fqdn.Name, d.source, since)...)
	} else {
		names = append(names, d.query(e, fqdn.Name, d.source, keys)...)
		support.MarkAssetMonitored(e.Session, e.Entity, d.source)
	}

	if len(names) > 0 {
		d.process(e, names)
	}
	return nil
}

func (d *dnsrepo) lookup(e *et.Event, name string, src *et.Source, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), d.source, since)
}

func (d *dnsrepo) query(e *et.Event, name string, src *et.Source, keys []string) []*dbt.Entity {
	var names []string

	for _, key := range keys {
		var req *http.Request

		if key == "" {
			req = &http.Request{URL: "https://dnsrepo.noc.org/?domain=" + name}
		} else {
			req = &http.Request{
				URL: "https://dnsrepo.noc.org/api/?apikey=" + key + "&search=" + name + "&limit=5000",
			}
		}

		d.rlimit.Take()
		if resp, err := http.RequestWebPage(context.TODO(), req); err == nil {
			if key == "" {
				names = append(names, d.parseHTML(e, resp.Body)...)
			} else {
				names = append(names, d.parseJSON(e, resp.Body)...)
			}
			break
		} else {
			e.Session.Log().Error(fmt.Sprintf("Failed to use the API endpoint: %v", err),
				slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
		}
	}

	return d.store(e, names)
}

func (d *dnsrepo) parseHTML(e *et.Event, body string) []string {
	var names []string

	for _, sub := range support.ScrapeSubdomainNames(body) {
		if sub != "" {
			// if the subdomain is not in scope, skip it
			name := http.CleanName(sub)
			if _, conf := e.Session.Scope().IsAssetInScope(&domain.FQDN{Name: name}, 0); conf > 0 {
				names = append(names, name)
			}
		}
	}

	return names
}

func (d *dnsrepo) parseJSON(e *et.Event, body string) []string {
	set := stringset.New()
	defer set.Close()

	var resp struct {
		Results []struct {
			Domain string   `json:"domain"`
			Alias  string   `json:"cname"`
			IPv4   []string `json:"ipv4"`
			IPv6   []string `json:"ipv6"`
		} `json:"results"`
	}

	if err := json.Unmarshal([]byte("{\"results\":"+body+"}"), &resp); err != nil {
		return set.Slice()
	}

	for _, r := range resp.Results {
		for _, sub := range []string{r.Domain, r.Alias} {
			if slen := len(sub); slen > 0 {
				name := sub
				// remove an ending dot from the name
				if sub[slen-1] == '.' {
					name = sub[:slen-1]
				}
				// if the subdomain is not in scope, skip it
				if _, conf := e.Session.Scope().IsAssetInScope(&domain.FQDN{Name: name}, 0); conf > 0 {
					set.Insert(name)
				}
			}
		}
	}

	return set.Slice()
}

func (d *dnsrepo) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, d.source, d.name, d.name+"-Handler")
}

func (d *dnsrepo) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, d.source)
}
