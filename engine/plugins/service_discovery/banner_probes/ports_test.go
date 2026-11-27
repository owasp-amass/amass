// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package banner_probes

import (
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
)

// A configuration without ports probes every port the catalog knows.
func TestCatalogPortsAreDefaults(t *testing.T) {
	cat, err := loadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range cat.probedPorts() {
		if !slices.Contains(config.DefaultPorts, p) {
			t.Errorf("port %d in protocols.json is missing from config.DefaultPorts", p)
		}
	}
}
