// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

func TestIdentityProviderFor(t *testing.T) {
	if p, ok := IdentityProviderFor("utica-products.okta.com"); !ok || p.Name != "Okta" || p.TenantType != "okta_org" {
		t.Errorf("an Okta tenant host gave %+v, %v", p, ok)
	}
	if p, ok := IdentityProviderFor("Example.US.Auth0.com."); !ok || p.Name != "Auth0" {
		t.Errorf("an Auth0 tenant host gave %+v, %v", p, ok)
	}
	if _, ok := IdentityProviderFor("sts.owasp.org"); ok {
		t.Error("an organization's own federation server matched a provider")
	}
	if _, ok := IdentityProviderFor("notokta.com"); ok {
		t.Error("a suffix matched inside a label")
	}
	if !IsLoginLabel("SSO") || IsLoginLabel("www") {
		t.Error("login labels are wrong")
	}
}
