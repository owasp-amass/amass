// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scrape

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/time/rate"
)

type ipverse struct {
	name   string
	fmtstr string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewIPVerse() et.Plugin {
	limit := rate.Every(2 * time.Second)

	return &ipverse{
		name:   "GitHub-IPVerse",
		fmtstr: "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/%d/aggregated.json",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "GitHub-IPVerse",
			Confidence: 90,
		},
	}
}

func (v *ipverse) Name() string {
	return v.name
}

func (v *ipverse) Start(r et.Registry) error {
	v.log = r.Log().WithGroup("plugin").With("name", v.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       v,
		Name:         v.name + "-Handler",
		Position:     30,
		Exclusive:    true,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.Netblock)},
		EventType:    oam.AutonomousSystem,
		Callback:     v.check,
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

	// asked once within the TTL; a failed request is asked again later
	since, err := support.TTLStartTime(e.Session.Config(), string(oam.AutonomousSystem), string(oam.Netblock), v.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, v.source, since) {
		return nil
	}

	rec := v.query(e.Session, as.Number)
	if rec == nil {
		return nil
	}

	support.MarkAssetMonitored(e.Session, e.Entity, v.source)
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

func (v *ipverse) query(sess et.Session, asn int) *record {
	body, ok := fetchPage(sess, v.rlimit, fmt.Sprintf(v.fmtstr, asn))
	if !ok {
		return nil
	}

	var result record
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return nil
	}
	return &result
}
