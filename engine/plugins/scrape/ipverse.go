// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scrape

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"go.uber.org/ratelimit"
)

type ipverse struct {
	name   string
	fmtstr string
	log    *slog.Logger
	rlimit ratelimit.Limiter
	source *et.Source
	asns   map[int]struct{}
}

func NewIPVerse() et.Plugin {
	return &ipverse{
		name:   "GitHub-IPVerse",
		fmtstr: "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/%d/aggregated.json",
		rlimit: ratelimit.New(5, ratelimit.WithoutSlack),
		source: &et.Source{
			Name:       "GitHub-IPVerse",
			Confidence: 90,
		},
		asns: make(map[int]struct{}),
	}
}

func (v *ipverse) Name() string {
	return v.name
}

func (v *ipverse) Start(r et.Registry) error {
	v.log = r.Log().WithGroup("plugin").With("name", v.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     v,
		Name:       v.name + "-Handler",
		Priority:   1,
		Transforms: []string{string(oam.Netblock)},
		EventType:  oam.AutonomousSystem,
		Callback:   v.check,
	}); err != nil {
		return err
	}

	v.log.Info("Plugin started")
	return nil
}

func (v *ipverse) Stop() {
	v.log.Info("Plugin stopped")
}

func (v *ipverse) check(e *et.Event) error {
	as, ok := e.Entity.Asset.(*oamnet.AutonomousSystem)
	if !ok {
		return errors.New("failed to extract the AutonomousSystem asset")
	}

	if _, found := v.asns[as.Number]; found {
		return nil
	}

	rec := v.query(e.Entity)
	if rec == nil {
		return nil
	}
	v.asns[as.Number] = struct{}{}

	for _, cidr := range append(rec.CIDRs.IPv4, rec.CIDRs.IPv6...) {
		_ = support.AddNetblock(e.Session, cidr, as.Number, v.source)
	}
	return nil
}

type record struct {
	ASN   int `json:"asn"`
	CIDRs struct {
		IPv4 []string `json:"ipv4"`
		IPv6 []string `json:"ipv6"`
	} `json:"subnets"`
}

func (v *ipverse) query(asset *dbt.Entity) *record {
	v.rlimit.Take()

	as := asset.Asset.(*oamnet.AutonomousSystem)
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: fmt.Sprintf(v.fmtstr, as.Number)})
	if err != nil || resp.Body == "" {
		return nil
	}

	var result record
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		return nil
	}
	return &result
}
