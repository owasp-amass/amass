// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"context"
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
)

// phoneDetails records, offline, what a phone number's numbering plan says
// about it: its line type (line_type: fixed_line, mobile, toll_free, voip,
// …) and the area it was issued in (phone_region). Its country is already
// the Phone's country_abbrev. No carrier is recorded: numbers move between
// carriers, so the plan's original carrier is often wrong.
type phoneDetails struct {
	name string
	log  *slog.Logger
}

func NewPhoneDetails() et.Plugin { return &phoneDetails{name: "Phone-Details"} }

func (pd *phoneDetails) Name() string { return pd.name }

func (pd *phoneDetails) Start(r et.Registry) error {
	pd.log = r.Log().WithGroup("plugin").With("name", pd.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       pd,
		Name:         pd.name + "-Handler",
		Position:     1,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.Phone)},
		EventType:    oam.Phone,
		Callback:     pd.check,
	}); err != nil {
		return err
	}

	pd.log.Info("Plugin started")
	return nil
}

func (pd *phoneDetails) Stop() { pd.log.Info("Plugin stopped") }

func (pd *phoneDetails) check(e *et.Event) error {
	phone, ok := e.Entity.Asset.(*oamcon.Phone)
	if !ok || phone.E164 == "" {
		return nil
	}

	lineType, region := support.PhoneDetails(phone.E164)
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()
	support.AddProperty(ctx, e.Session, e.Entity, "line_type", lineType)
	support.AddProperty(ctx, e.Session, e.Entity, "phone_region", region)
	return nil
}
