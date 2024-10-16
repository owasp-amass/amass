// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/source"
	"go.uber.org/ratelimit"
)

type Prospeo struct {
	name     string
	accturl  string
	counturl string
	queryurl string
	log      *slog.Logger
	rlimit   ratelimit.Limiter
	source   *source.Source
}

func NewProspeo() et.Plugin {
	return &Prospeo{
		name:     "Prospeo",
		accturl:  "https://api.prospeo.io/account-information",
		counturl: "https://api.prospeo.io/email-count",
		queryurl: "https://api.prospeo.io/domain-search",
		rlimit:   ratelimit.New(15, ratelimit.WithoutSlack),
		source: &source.Source{
			Name:       "Prospeo",
			Confidence: 80,
		},
	}
}

func (p *Prospeo) Name() string {
	return p.name
}

func (p *Prospeo) Start(r et.Registry) error {
	p.log = r.Log().WithGroup("plugin").With("name", p.name)

	name := p.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     p,
		Name:       name,
		Transforms: []string{string(oam.EmailAddress)},
		EventType:  oam.FQDN,
		Callback:   p.check,
	}); err != nil {
		return err
	}

	p.log.Info("Plugin started")
	return nil
}

func (p *Prospeo) Stop() {
	p.log.Info("Plugin stopped")
}

func (p *Prospeo) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if a, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 || a == nil {
		return nil
	} else if f, ok := a.(*domain.FQDN); !ok || f == nil || !strings.EqualFold(fqdn.Name, f.Name) {
		return nil
	}

	src := support.GetSource(e.Session, p.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.EmailAddress), p.name)
	if err != nil {
		return err
	}

	var names []*dbt.Asset
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		names = append(names, p.lookup(e, fqdn.Name, src, since)...)
	} else {
		names = append(names, p.query(e, fqdn.Name, src)...)
		support.MarkAssetMonitored(e.Session, e.Asset, src)
	}

	if len(names) > 0 {
		p.process(e, names, src)
	}
	return nil
}

func (p *Prospeo) lookup(e *et.Event, name string, src *dbt.Asset, since time.Time) []*dbt.Asset {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.EmailAddress), src, since)
}

func (p *Prospeo) query(e *et.Event, name string, src *dbt.Asset) []*dbt.Asset {
	key, err := support.GetAPI(p.name, e)
	if err != nil {
		return []*dbt.Asset{}
	}

	rcreds, err := p.accountType(key)
	if err != nil || key == "" {
		return []*dbt.Asset{}
	}

	count, err := p.count(name, key)
	if err != nil {
		return []*dbt.Asset{}
	}

	limit := rcreds * 50
	if limit > count {
		limit = count
	}

	p.rlimit.Take()
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		Method: "POST",
		Body:   `{"company": "` + name + `", "limit": ` + strconv.Itoa(limit) + `}`,
		URL:    p.queryurl,
		Header: http.Header{"Content-Type": []string{"application/json"}, "X-KEY": []string{key}},
	})
	if err != nil {
		return []*dbt.Asset{}
	}

	var r struct {
		Response struct {
			Emails []struct {
				Email string `json:"email"`
			} `json:"email_list"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &r); err != nil {
		return []*dbt.Asset{}
	}

	var emails []string
	for _, e := range r.Response.Emails {
		emails = append(emails, e.Email)
	}
	return p.store(e, emails, src)
}

func (p *Prospeo) store(e *et.Event, emails []string, src *dbt.Asset) []*dbt.Asset {
	return support.StoreEmailsWithSource(e.Session, emails, src, p.name, p.name+"-Handler")
}

func (p *Prospeo) process(e *et.Event, assets []*dbt.Asset, src *dbt.Asset) {
	support.ProcessEmailsWithSource(e, assets, src)
}

func (p *Prospeo) accountType(key string) (int, error) {
	p.rlimit.Take()
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		Method: "POST",
		URL:    p.accturl,
		Header: http.Header{"Content-Type": []string{"application/json"}, "X-KEY": []string{key}},
	})
	if err != nil {
		return 0, err
	}

	var r struct {
		Response struct {
			RemainingCredits int `json:"remaining_credits"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &r); err != nil {
		return 0, err
	}
	return r.Response.RemainingCredits, nil
}

func (p *Prospeo) count(domain string, key string) (int, error) {
	p.rlimit.Take()
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		Method: "POST",
		Body:   `{"domain": "` + domain + `"}`,
		URL:    p.counturl,
		Header: http.Header{"Content-Type": []string{"application/json"}, "X-KEY": []string{key}},
	})
	if err != nil {
		return 0, err
	}

	var r struct {
		Response struct {
			Count int `json:"count"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &r); err != nil {
		return 0, err
	}
	return r.Response.Count, nil
}
