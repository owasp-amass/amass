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
	"strconv"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/dns"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
	"go.uber.org/ratelimit"
)

type urlscan struct {
	name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewURLScan() et.Plugin {
	return &urlscan{
		name:   "URLScan",
		rlimit: ratelimit.New(5, ratelimit.WithoutSlack),
	}
}

func (u *urlscan) Name() string {
	return u.name
}

func (u *urlscan) Start(r et.Registry) error {
	u.log = r.Log().WithGroup("plugin").With("name", u.name)

	name := u.name + "-FQDN-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     u,
		Name:       name,
		Transforms: []string{string(oam.FQDN)},
		EventType:  oam.FQDN,
		Callback:   u.fqdnCheck,
	}); err != nil {
		return err
	}

	name = u.name + "-ASN-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     u,
		Name:       name,
		Transforms: []string{string(oam.FQDN)},
		EventType:  oam.AutonomousSystem,
		Callback:   u.asnCheck,
	}); err != nil {
		return err
	}

	u.log.Info("Plugin started")
	return nil
}

func (u *urlscan) Stop() {
	u.log.Info("Plugin stopped")
}

func (u *urlscan) fqdnCheck(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	var keys []string
	ds := e.Session.Config().GetDataSourceConfig(u.name)
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

	var body string
	for _, key := range keys {
		u.rlimit.Take()

		b, err := u.query("domain:"+fqdn.Name, key)
		if err == nil {
			body = b
			break
		}

		e.Session.Log().Error(fmt.Sprintf("Failed to use the API endpoint: %v", err),
			slog.Group("plugin", "name", u.name, "handler", u.name+"-ASN-Handler"))
	}

	if body != "" {
		u.process(e, body)
	}
	return nil
}

func (u *urlscan) asnCheck(e *et.Event) error {
	asn, ok := e.Entity.Asset.(*network.AutonomousSystem)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	var keys []string
	ds := e.Session.Config().GetDataSourceConfig(u.name)
	if ds != nil {
		for _, cred := range ds.Creds {
			keys = append(keys, cred.Apikey)
		}
	}
	// add an empty API key
	keys = append(keys, "")

	var found bool
	for _, num := range e.Session.Config().Scope.ASNs {
		if num == asn.Number {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	var body string
	for _, key := range keys {
		u.rlimit.Take()

		b, err := u.query("asn:AS"+strconv.Itoa(asn.Number), key)
		if err == nil {
			body = b
			break
		}

		e.Session.Log().Error(fmt.Sprintf("Failed to use the API endpoint: %v", err),
			slog.Group("plugin", "name", u.name, "handler", u.name+"-ASN-Handler"))
	}

	if body != "" {
		u.process(e, body)
	}
	return nil
}

func (u *urlscan) query(q, key string) (string, error) {
	hdr := make(http.Header)
	hdr["Content-Type"] = []string{"application/json"}
	if key != "" {
		hdr["API-Key"] = []string{key}
	}

	req := &http.Request{
		Header: hdr,
		URL:    "https://urlscan.io/api/v1/search/?q=" + q,
	}

	resp, err := http.RequestWebPage(context.TODO(), req)
	if err != nil {
		return "", err
	}
	return resp.Body, nil
}

func (u *urlscan) process(e *et.Event, body string) {
	var resp struct {
		Results []struct {
			Page struct {
				FQDN   string `json:"domain"`
				Apex   string `json:"apexDomain"`
				PTR    string `json:"ptr"`
				IP     string `json:"ip"`
				ASN    string `json:"asn"`
				Server string `json:"server"`
			} `json:"page"`
		} `json:"results"`
	}

	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return
	}

	var wg sync.WaitGroup
	for _, r := range resp.Results {
		for _, sub := range []string{r.Page.FQDN, r.Page.Apex, r.Page.PTR} {
			if sub != "" {
				fqdn := dns.RemoveAsteriskLabel(sub)
				// if the subdomain is not in scope, skip it
				name := strings.ToLower(strings.TrimSpace(fqdn))
				if _, conf := e.Session.Scope().IsAssetInScope(&domain.FQDN{Name: name}, 0); conf > 0 {
					wg.Add(1)

					support.AppendToDBQueue(func() {
						defer wg.Done()

						if e.Session.Done() {
							return
						}

						fqdn, err := e.Session.DB().Create(nil, "", &domain.FQDN{Name: name})
						if err != nil {
							e.Session.Log().Error(err.Error())
							return
						}
						if fqdn != nil {
							_, _ = e.Session.DB().Create(fqdn, "source", &et.Source{Name: u.name})
							_ = e.Dispatcher.DispatchEvent(&et.Event{
								Name:    name,
								Asset:   fqdn,
								Session: e.Session,
							})
						}
					})
				}
			}
		}
	}
	wg.Wait()
}
