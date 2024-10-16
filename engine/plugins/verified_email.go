// Copyright © by Jeff Foley 2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"errors"
	"log/slog"

	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
)

type verifiedEmail struct {
	name string
	log  *slog.Logger
}

func NewVerifiedEmail() et.Plugin {
	return &verifiedEmail{
		name: "Verified-Email",
	}
}

func (v *verifiedEmail) Name() string {
	return v.name
}

func (v *verifiedEmail) Start(r et.Registry) error {
	v.log = r.Log().WithGroup("plugin").With("name", v.name)

	name := v.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     v,
		Name:       name,
		Transforms: []string{"emailaddress"},
		Priority:   9,
		EventType:  oam.EmailAddress,
		Callback:   v.check,
	}); err != nil {
		return err
	}

	v.log.Info("Plugin started")
	return nil
}

func (v *verifiedEmail) Stop() {
	v.log.Info("Plugin stopped")
}

func (v *verifiedEmail) check(e *et.Event) error {
	email, ok := e.Asset.Asset.(*contact.EmailAddress)
	if !ok {
		return errors.New("failed to extract the EmailAddress asset")
	}

	var storeEmail bool
	if meta, ok := e.Meta.(*et.EmailMeta); ok && meta.VerifyAttempted {
		if meta.Verified {
			storeEmail = true
		}
	} else {
		storeEmail = true
	}

	if storeEmail {
		_, _ = e.Session.DB().Create(nil, "", email)
	}
	return nil
}
