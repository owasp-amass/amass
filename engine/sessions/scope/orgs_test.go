// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope_test

import (
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// A scope given an organization's acronym still takes it in once a merge
// shows its full name, by the name it claims.
func TestScopeMatchesClaimedNames(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.Scope().AddOrgByName("OCLC")

	o := &oamorg.Organization{ID: "oclc:1", Name: "Online Computer Library Center"}
	sess.Asset(t, o)
	if _, conf := sess.Scope().IsAssetInScope(o, 100); conf != 0 {
		t.Fatal("the full name matched the acronym by itself")
	}

	other := &oamorg.Organization{ID: "oclc:2", Name: "Online Computer Library Center"}
	claim := sess.Asset(t, &oamgen.Identifier{UniqueID: oamgen.OrganizationName + ":OCLC", ID: "OCLC",
		Type: oamgen.OrganizationName})
	sess.Edge(t, sess.Asset(t, other), &oamgen.SimpleRelation{Name: "id"}, claim)
	if _, conf := sess.Scope().IsAssetInScope(other, 100); conf != 100 {
		t.Errorf("the organization claiming the acronym: confidence %d", conf)
	}
}
