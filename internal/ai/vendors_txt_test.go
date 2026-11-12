// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import "testing"

func TestTXTVendors(t *testing.T) {
	records := []string{
		"google-site-verification=abc123",
		"MS=ms12345678",
		"v=spf1 ip4:149.43.0.0/16 include:_spf.google.com include:spf.protection.outlook.com " +
			"include:u123.wl.sendgrid.net include:_spf.example.org redirect=_spf.mailgun.org -all",
		"docusign=0a1b2c",
		"some unrelated note mentioning sendgrid.net",
	}

	got := map[string]string{}
	for _, v := range txtVendors(records, "colgate.edu") {
		got[v.Vendor+"|"+v.Kind] = v.Via
	}

	for _, want := range []string{
		"Google|" + kindVerification,
		"Microsoft 365|" + kindVerification,
		"DocuSign|" + kindVerification,
		"Google Workspace|" + kindSPF,
		"Microsoft 365|" + kindSPF,
		"Twilio SendGrid|" + kindSPF,
		"Mailgun|" + kindSPF,
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if len(got) != 7 {
		t.Errorf("got %d vendors, want 7: %v", len(got), got)
	}
}
