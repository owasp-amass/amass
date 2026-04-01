// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
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
		Plugin:       p,
		Name:         name,
		Position:     29,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.Identifier)},
		EventType:    oam.FQDN,
		Callback:     p.check,
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
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, p.source, since) {
		names = append(names, p.query(e, fqdn.Name)...)
		support.MarkAssetMonitored(e.Session, e.Entity, p.source)
	}

	if len(names) > 0 {
		p.process(e, names)
	}
	return nil
}

func (p *Prospeo) query(e *et.Event, name string) []*dbt.Entity {
	key, err := support.GetAPI(p.name, e)
	if err != nil {
		return nil
	}

	rcreds, err := p.accountType(e.Session, key)
	if err != nil || key == "" {
		return nil
	}

	count, err := p.count(e.Session, name, key)
	if err != nil {
		return nil
	}
	limit := min(rcreds*50, count)

	_ = p.rlimit.Wait(e.Session.Ctx())
	e.Session.NetSem().Acquire()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		Method: "POST",
		Body:   `{"company": "` + name + `", "limit": ` + strconv.Itoa(limit) + `}`,
		URL:    p.queryurl,
		Header: amasshttp.Header{"Content-Type": []string{"application/json"}, "X-KEY": []string{key}},
	})
	e.Session.NetSem().Release()
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

func (p *Prospeo) accountType(sess et.Session, key string) (int, error) {
	_ = p.rlimit.Wait(sess.Ctx())

	sess.NetSem().Acquire()
	rctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(rctx, sess.Clients().General, &amasshttp.Request{
		Method: "POST",
		URL:    p.accturl,
		Header: amasshttp.Header{"Content-Type": []string{"application/json"}, "X-KEY": []string{key}},
	})
	sess.NetSem().Release()
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

func (p *Prospeo) count(sess et.Session, domain string, key string) (int, error) {
	_ = p.rlimit.Wait(sess.Ctx())

	sess.NetSem().Acquire()
	rctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(rctx, sess.Clients().General, &amasshttp.Request{
		Method: "POST",
		Body:   `{"domain": "` + domain + `"}`,
		URL:    p.counturl,
		Header: amasshttp.Header{"Content-Type": []string{"application/json"}, "X-KEY": []string{key}},
	})
	sess.NetSem().Release()
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
