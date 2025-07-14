// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"golang.org/x/time/rate"
)

type Prospeo struct {
	name     string
	accturl  string
	counturl string
	queryurl string
	log      *slog.Logger
	rlimit   *rate.Limiter
	source   *et.Source
}

func NewProspeo() et.Plugin {
	limit := rate.Every(15 * time.Second)

	return &Prospeo{
		name:     "Prospeo",
		accturl:  "https://api.prospeo.io/account-information",
		counturl: "https://api.prospeo.io/email-count",
		queryurl: "https://api.prospeo.io/domain-search",
		rlimit:   rate.NewLimiter(limit, 1),
		source: &et.Source{
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
		Priority:   9,
		Transforms: []string{string(oam.Identifier)},
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
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.Identifier), p.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, p.source, since) {
		names = append(names, p.lookup(e, fqdn.Name, since)...)
	} else {
		names = append(names, p.query(e, fqdn.Name)...)
		support.MarkAssetMonitored(e.Session, e.Entity, p.source)
	}

	if len(names) > 0 {
		p.process(e, names)
	}
	return nil
}

func (p *Prospeo) lookup(e *et.Event, name string, since time.Time) []*dbt.Entity {
	var emails []*dbt.Entity

	for _, e := range support.SourceToAssetsWithinTTL(e.Session, name, string(oam.Identifier), p.source, since) {
		if email, ok := e.Asset.(*general.Identifier); ok && email != nil && email.Type == general.EmailAddress {
			emails = append(emails, e)
		}
	}

	return emails
}

func (p *Prospeo) query(e *et.Event, name string) []*dbt.Entity {
	key, err := support.GetAPI(p.name, e)
	if err != nil {
		return nil
	}

	rcreds, err := p.accountType(key)
	if err != nil || key == "" {
		return nil
	}

	count, err := p.count(name, key)
	if err != nil {
		return nil
	}

	limit := rcreds * 50
	if limit > count {
		limit = count
	}

	_ = p.rlimit.Wait(context.TODO())
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		Method: "POST",
		Body:   `{"company": "` + name + `", "limit": ` + strconv.Itoa(limit) + `}`,
		URL:    p.queryurl,
		Header: http.Header{"Content-Type": []string{"application/json"}, "X-KEY": []string{key}},
	})
	if err != nil {
		return nil
	}

	var r struct {
		Response struct {
			Emails []struct {
				Email string `json:"email"`
			} `json:"email_list"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &r); err != nil {
		return nil
	}

	var emails []string
	for _, e := range r.Response.Emails {
		emails = append(emails, e.Email)
	}
	return p.store(e, emails)
}

func (p *Prospeo) store(e *et.Event, emails []string) []*dbt.Entity {
	return support.StoreEmailsWithSource(e.Session, emails, p.source, p.name, p.name+"-Handler")
}

func (p *Prospeo) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessEmailsWithSource(e, assets, p.source)
}

func (p *Prospeo) accountType(key string) (int, error) {
	_ = p.rlimit.Wait(context.TODO())

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
	_ = p.rlimit.Wait(context.TODO())

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
