// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

func TestIdentifyDistribution(t *testing.T) {
	for _, tc := range []struct {
		evidence, version, name, family, revision string
	}{
		{"Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k", "2.4.37", "Red Hat Enterprise Linux", "redhat", ""},
		{"Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k", "1.1.1k", "Red Hat Enterprise Linux", "redhat", ""},
		{"Apache/2.4.58 (Ubuntu)", "2.4.58", "Ubuntu", "ubuntu", ""},
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "9.6p1", "Ubuntu", "ubuntu", "3ubuntu13.5"},
		{"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", "9.2p1", "Debian", "debian", "2+deb12u3"},
		{"PHP/8.1.2-1ubuntu2.14", "8.1.2", "Ubuntu", "ubuntu", "1ubuntu2.14"},
		{"PHP/8.2.7-1~deb12u1", "8.2.7", "Debian", "debian", "1~deb12u1"},
		// the revision belongs to the version it follows
		{"Apache/2.4.41 (Ubuntu) PHP/7.4.3-4ubuntu2.20", "2.4.41", "Ubuntu", "ubuntu", ""},
		{"Apache/2.4.41 (Ubuntu) PHP/7.4.3-4ubuntu2.20", "7.4.3", "Ubuntu", "ubuntu", "4ubuntu2.20"},
		{"Apache/2.4.37 (Oracle Linux Server) OpenSSL/1.1.1k", "2.4.37", "Oracle Linux", "", ""},
		{"Apache/2.4.62 (Rocky Linux)", "2.4.62", "Rocky Linux", "", ""},
		{"nginx/1.29.8", "1.29.8", "", "", ""},
		{"Apache", "", "", "", ""},
	} {
		name, family, rev := identifyDistribution(tc.evidence, tc.version)
		if name != tc.name || family != tc.family || rev != tc.revision {
			t.Errorf("%q for %s gave %q %q %q, want %q %q %q", tc.evidence, tc.version, name, family, rev,
				tc.name, tc.family, tc.revision)
		}
	}
}

// Identified products carry the distribution their own header or banner
// names, and the package version when it gives the revision.
func TestIdentifyProductsDistribution(t *testing.T) {
	ssh := graph.Asset{ID: "s", Type: "Service", Content: map[string]any{"service_type": "ssh",
		"output": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"}}
	ids := identifyProducts(ssh)
	if len(ids) != 1 || ids[0].Distribution != "Ubuntu" || ids[0].Package != "8.9p1-3ubuntu0.10" ||
		ids[0].Label() != "OpenSSH 8.9p1 (Ubuntu package 8.9p1-3ubuntu0.10)" {
		t.Errorf("ssh: %+v", ids)
	}

	web := graph.Asset{ID: "w", Type: "Service", Content: map[string]any{"service_type": "web-service",
		"attributes": map[string]any{"server": []any{"Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k"},
			"x-powered-by": []any{"PHP/7.2.24"}}}}
	for _, p := range identifyProducts(web) {
		want := "Red Hat Enterprise Linux"
		if p.Product == "PHP" {
			want = "" // its own header names no distribution
		}
		if p.Distribution != want {
			t.Errorf("%s: distribution %q, want %q", p.Product, p.Distribution, want)
		}
	}
}
