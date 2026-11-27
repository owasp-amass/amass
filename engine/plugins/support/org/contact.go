// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"fmt"
	"strings"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// LinkContactOrg creates (or reuses) the organization a contact names, linked
// from its ContactRecord (organization), and dispatches it. It returns the
// organization, or nil. A contact's organization is stored after the rest of
// the contact, so the organization's own handlers find the contact complete.
func LinkContactOrg(e *et.Event, cr *dbt.Entity, name string, src *et.Source) *dbt.Entity {
	name = strings.TrimSpace(name)
	if cr == nil || name == "" {
		return nil
	}

	orgent, err := CreateOrgAsset(e.Session, cr, &oamgen.SimpleRelation{Name: "organization"},
		&oamorg.Organization{Name: name}, src)
	if err != nil || orgent == nil {
		return nil
	}

	DispatchOrg(e, orgent)
	return orgent
}

// DispatchOrg sends an organization on as an event.
func DispatchOrg(e *et.Event, orgent *dbt.Entity) {
	o, ok := orgent.Asset.(*oamorg.Organization)
	if !ok {
		return
	}
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    fmt.Sprintf("%s:%s", o.Name, o.ID),
		Entity:  orgent,
		Session: e.Session,
	})
}
