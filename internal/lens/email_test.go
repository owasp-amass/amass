// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"strings"
	"testing"
)

// MX hosts are named by the provider that documents them, and a host no
// provider documents is left for the vendor names.
func TestMailProviderOf(t *testing.T) {
	rules := loadEmailRules()
	for host, want := range map[string]string{
		"smtp.google.com":                         "Google Workspace",
		"ASPMX.L.GOOGLE.COM.":                     "Google Workspace",
		"example-com.mail.protection.outlook.com": "Microsoft 365",
		"mx1.us2.ppe-hosted.com":                  "Proofpoint Essentials",
		"us-smtp-inbound-1.mimecast.com":          "Mimecast",
		"d123456a.ess.barracudanetworks.com":      "Barracuda Email Security Service",
		"mx1.example.iphmx.com":                   "Cisco Secure Email Cloud Gateway",
		"mx1.example.eu.iphmx.com":                "Cisco Secure Email Cloud Gateway",
		"mail.example.com":                        "",
		"google.com.example.net":                  "",
		"mail.protection.outlook.com.example.org": "",
	} {
		if got := mailProviderOf(rules, host); got != want {
			t.Errorf("mailProviderOf(%q) = %q, want %q", host, got, want)
		}
	}
	for _, p := range rules.MailProviders {
		if !strings.HasPrefix(p.Source, "https://") {
			t.Errorf("mail provider %s cites no documentation", p.Provider)
		}
	}
}
