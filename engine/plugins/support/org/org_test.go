// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"strings"
	"testing"

	et "github.com/owasp-amass/amass/v5/engine/types"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// A redaction placeholder is refused before the session or database is used.
func TestCreateOrgAssetRefusesPlaceholderNames(t *testing.T) {
	src := &et.Source{Name: "test", Confidence: 100}
	for _, name := range []string{"Registration Private", "REDACTED FOR PRIVACY", "Domain Admin",
		"Administrator, Domain ContactMiddleName"} {
		_, err := CreateOrgAsset(nil, nil, nil, &oamorg.Organization{Name: name}, src)
		if err == nil || !strings.Contains(err.Error(), "placeholder") {
			t.Errorf("%q: err = %v, want a placeholder refusal", name, err)
		}
	}
}
