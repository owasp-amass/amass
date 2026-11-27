// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"errors"
	"log/slog"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
)

type contactrec struct {
	name       string
	log        *slog.Logger
	transforms []string
	source     *et.Source
}

func NewContacts() et.Plugin {
	return &contactrec{
		name: "Contract-Record-Expansion",
		transforms: []string{
			string(oam.URL),
			string(oam.Person),
			string(oam.Organization),
			string(oam.StreetAddress),
			string(oam.Identifier),
			string(oam.Phone),
		},
		source: &et.Source{
			Name:       "Contract-Record-Expansion",
			Confidence: 100,
		},
	}
}

func (cr *contactrec) Name() string {
	return cr.name
}

func (cr *contactrec) Start(r et.Registry) error {
	cr.log = r.Log().WithGroup("plugin").With("name", cr.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       cr,
		Name:         cr.name,
		Position:     40,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   cr.transforms,
		EventType:    oam.ContactRecord,
		Callback:     cr.check,
	}); err != nil {
		return err
	}

	cr.log.Info("Plugin started")
	return nil
}

func (cr *contactrec) Stop() {
	cr.log.Info("Plugin stopped")
}

func (cr *contactrec) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*contact.ContactRecord)
	if !ok {
		return errors.New("failed to extract the ContactRecord asset")
	}

	matches, err := e.Session.Config().CheckTransformations(
		string(oam.ContactRecord), append(cr.transforms, cr.name)...)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	// What any source attached to the contact record is dispatched again.
	conrec := e.Entity.Asset.(*contact.ContactRecord)
	if findings := support.StoredFindings(e, e.Entity, "ContactRecord: "+conrec.DiscoveredAt, cr.name, matches,
		map[string][]string{
			string(oam.Person):        {"person"},
			string(oam.Organization):  {"organization"},
			string(oam.StreetAddress): {"street_address"},
			string(oam.Identifier):    {"id"},
			string(oam.Phone):         {"phone"},
			string(oam.URL):           {"url"},
		}, nil); len(findings) > 0 {
		cr.process(e, findings)
	}
	return nil
}

func (cr *contactrec) process(e *et.Event, findings []*support.Finding) {
	support.ProcessAssetsWithSource(e, findings, cr.source, cr.name, cr.name+"-Handler")
}
