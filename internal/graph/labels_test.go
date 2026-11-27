// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import "testing"

// A service is named by where it listens, its unique ID without the hash of
// what answered; one whose ID names no listening place keeps its type.
func TestServiceLabel(t *testing.T) {
	for _, c := range []struct {
		content map[string]any
		want    string
	}{
		{map[string]any{"unique_id": "www.owasp.org:tcp:443-57189b4b0f07b1e3", "service_type": "web-service"},
			"www.owasp.org:tcp:443"},
		{map[string]any{"unique_id": "my-host.owasp.org:tcp:22-0a1b2c3d4e5f6a7b"}, "my-host.owasp.org:tcp:22"},
		{map[string]any{"unique_id": "owasp.org:443"}, "owasp.org:443"},
		{map[string]any{"unique_id": "c3d4", "service_type": "smtp"}, "smtp"},
		{map[string]any{"service_type": "web-service"}, "web-service"},
	} {
		if got := AssetLabel(Asset{Type: "Service", Content: c.content}); got != c.want {
			t.Errorf("AssetLabel(%v) = %q, want %q", c.content, got, c.want)
		}
	}
}
