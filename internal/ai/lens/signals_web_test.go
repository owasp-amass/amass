// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"testing"

	"github.com/owasp-amass/amass/v5/internal/fingerprint"
)

// TestWebSignalsUseTheFingerprintContract keeps the catalog's property
// names equal to the names every collector stores.
func TestWebSignalsUseTheFingerprintContract(t *testing.T) {
	want := map[string]string{
		"shared_analytics_id": fingerprint.AnalyticsID,
		"same_favicon":        fingerprint.FaviconMMH3,
		"same_page_content":   fingerprint.BodySHA256,
		"same_page_title":     fingerprint.Title,
		"ssh_host_key_reuse":  fingerprint.SSHHostKey,
	}
	for id, prop := range want {
		def, ok := LookupOwnershipSignal(id)
		if !ok || def.Params.Property != prop {
			t.Errorf("signal %s reads %q, collectors store %q", id, def.Params.Property, prop)
		}
	}
}

func TestClonedSitesAreNeverProposed(t *testing.T) {
	// A copy of a page carries its analytics IDs, favicon, content and title.
	clone := []GapSignal{{Signal: "shared_analytics_id"}, {Signal: "same_favicon"}, {Signal: "same_page_content"},
		{Signal: "same_page_title"}}
	if _, d := ScoreGap(clone, true); d != GapReview {
		t.Errorf("a cloned site = %s, want review", d)
	}
}
