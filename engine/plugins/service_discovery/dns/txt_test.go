// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import "testing"

func TestIsVerificationRecord(t *testing.T) {
	for _, rec := range []string{
		"autodesk-domain-verification=Zx81",
		"e2ma-verification=1f2e3d",
		"jamf-site-verification=AbC123",
		"perplexity-ai-domain-verification-j105av=xyz",
		"sitecore-domain-verification=s1",
		"google-site-verification=abc123",
	} {
		if !IsVerificationRecord(rec) {
			t.Errorf("%q not recognized", rec)
		}
	}

	// Azure App Service publishes its verification ID under the asuid name
	// with no prefix, so an asuid= value names no service.
	for _, rec := range []string{"asuid=0123456789abcdef", "v=spf1 include:_spf.google.com -all"} {
		if IsVerificationRecord(rec) {
			t.Errorf("%q recognized", rec)
		}
	}
}

func TestVerificationPrefixesNameOrganizations(t *testing.T) {
	for prefix, o := range prefixes {
		if o == nil || o.Name == "" {
			t.Errorf("prefix %q names no organization", prefix)
		}
	}
}
