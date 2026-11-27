// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package osm collects organization phone numbers from OpenStreetMap through the
// public Overpass API, a worldwide, keyless source. For an enumerated
// Organization it looks up map features whose name matches and that carry a
// phone (phone / contact:phone) tag, and stores each number as a Phone under a
// ContactRecord, with the OpenStreetMap feature URL as the evidence.
//
// This is a global source, unlike the US-specific funders, so it helps targets
// anywhere. It is keyless and runs by default, no setup required; it is politely
// rate-limited and follows the TTL cadence because Overpass is a shared
// community service.
// Because a map feature's name matching an organization does not prove it
// belongs to that organization, matching is conservative (normalized-name
// equality) and the stored confidence is modest; the numbers are observations
// carrying their source, not computed conclusions (see
// claude/government-funding-sources-spec.md).
package osm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	oam "github.com/owasp-amass/open-asset-model"
	"golang.org/x/time/rate"
)

type openstreetmap struct {
	name    string
	api     string
	rlimit  *rate.Limiter
	source  *et.Source
	log     *slog.Logger
	phones  *phones
	reverse *reverse
}

type phones struct {
	name   string
	plugin *openstreetmap
}

// NewOpenStreetMap returns the OpenStreetMap/Overpass phone collector.
func NewOpenStreetMap() et.Plugin {
	return &openstreetmap{
		name: "OpenStreetMap",
		api:  "https://overpass-api.de/api/interpreter",
		// Overpass is a shared community service; query it gently.
		rlimit: rate.NewLimiter(rate.Every(5*time.Second), 1),
		source: &et.Source{
			Name: "OpenStreetMap",
			// A matching feature name is suggestive, not proof of ownership.
			Confidence: 60,
		},
	}
}

func (o *openstreetmap) Name() string { return o.name }

func (o *openstreetmap) Start(r et.Registry) error {
	o.log = r.Log().WithGroup("plugin").With("name", o.name)

	o.phones = &phones{name: o.name + "-Phones-Handler", plugin: o}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       o,
		Name:         o.phones.name,
		Position:     42,
		Exclusive:    false,
		MaxInstances: support.MinHandlerInstances,
		Transforms: []string{
			string(oam.ContactRecord),
			string(oam.Phone),
		},
		EventType: oam.Organization,
		Callback:  o.phones.check,
	}); err != nil {
		return err
	}

	// The reverse direction: from a phone or an address to the organizations
	// tied to it, so an enumeration can pivot from a Phone or StreetAddress seed.
	o.reverse = &reverse{name: o.name + "-Reverse-Handler", plugin: o}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       o,
		Name:         o.reverse.name + "-Phone",
		Position:     42,
		Exclusive:    false,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.ContactRecord), string(oam.Organization)},
		EventType:    oam.Phone,
		Callback:     o.reverse.checkPhone,
	}); err != nil {
		return err
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       o,
		Name:         o.reverse.name + "-StreetAddress",
		Position:     42,
		Exclusive:    false,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.ContactRecord), string(oam.Organization)},
		EventType:    oam.StreetAddress,
		Callback:     o.reverse.checkAddress,
	}); err != nil {
		return err
	}

	o.log.Info("Plugin started")
	return nil
}

func (o *openstreetmap) Stop() { o.log.Info("Plugin stopped") }

// overpass posts an Overpass QL query and returns the response body.
func (o *openstreetmap) overpass(e *et.Event, query string) (string, error) {
	_ = support.WaitLimit(e.Session.Ctx(), o.rlimit)
	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 60*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL:    o.api,
		Method: "POST",
		Header: amasshttp.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
		Body:   "data=" + url.QueryEscape(query),
	})
	e.Session.NetSem().Release()
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %s", resp.Status)
	}
	if resp.Body == "" {
		return "", errors.New("empty body")
	}
	return resp.Body, nil
}
