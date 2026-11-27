// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"encoding/xml"
	"reflect"
	"strings"
	"testing"
)

func TestTenantID(t *testing.T) {
	for body, want := range map[string]string{
		`{"token_endpoint":"x","issuer":"https://sts.windows.net/72F988BF-86F1-41AF-91AB-2D7CD011DB47/","x":1}`: "72f988bf-86f1-41af-91ab-2d7cd011db47",
		`{"issuer" : "https://login.microsoftonline.com/0a1b2c3d-0000-1111-2222-333344445555/v2.0"}`:            "0a1b2c3d-0000-1111-2222-333344445555",
		`{"issuer":"https://login.microsoftonline.com/{tenantid}/v2.0"}`:                                        "",
		`{"error":"invalid_tenant"}`: "",
		`{"authorization_endpoint":"https://x/72f988bf-86f1-41af-91ab-2d7cd011db47/"}`: "",
	} {
		if got := tenantID(body); got != want {
			t.Errorf("tenantID(%s) = %q, want %q", body, got, want)
		}
	}
}

func TestNamespaceType(t *testing.T) {
	for body, want := range map[string]string{
		`<RealmInfo Success="true"><State>4</State><NameSpaceType>Managed</NameSpaceType></RealmInfo>`:    "managed",
		`<RealmInfo><NameSpaceType> Federated </NameSpaceType><AuthURL>https://sts</AuthURL></RealmInfo>`: "federated",
		`<RealmInfo><NameSpaceType>Unknown</NameSpaceType></RealmInfo>`:                                   "",
		`<RealmInfo></RealmInfo>`: "",
	} {
		if got := namespaceType(body); got != want {
			t.Errorf("namespaceType(%s) = %q, want %q", body, got, want)
		}
	}
}

func TestFederationSiblings(t *testing.T) {
	body := `<s:Envelope><s:Body><GetFederationInformationResponseMessage><Response><Domains>` +
		`<Domain>example.com</Domain><Domain>Example-Brand.NET.</Domain><Domain>mail.example.com</Domain>` +
		`<Domain>example.onmicrosoft.com</Domain><Domain>example.mail.onmicrosoft.com</Domain>` +
		`<Domain> partner.org </Domain><Domain>example-brand.net</Domain><Domain>localhost</Domain>` +
		`<a:Domain>other.example.io</a:Domain></Domains></Response></GetFederationInformationResponseMessage>` +
		`</s:Body></s:Envelope>`
	want := []string{"example-brand.net", "partner.org", "other.example.io"}
	if got := federationSiblings(body, "example.com"); !reflect.DeepEqual(got, want) {
		t.Errorf("siblings = %q, want %q", got, want)
	}
	if got := federationSiblings("<Error>no</Error>", "example.com"); len(got) != 0 {
		t.Errorf("siblings from an error = %q", got)
	}
}

// The request is well-formed XML asking about the domain.
func TestFederationRequest(t *testing.T) {
	req := federationRequest("example.com")
	if err := xml.Unmarshal([]byte(req), new(struct{})); err != nil {
		t.Fatalf("the request is not well-formed XML: %v", err)
	}
	if !strings.Contains(req, "<autodiscover:Domain>example.com</autodiscover:Domain>") ||
		!strings.Contains(req, fedInfoAction) {
		t.Errorf("request = %s", req)
	}
	if NewIdentity().Name() != "Identity" {
		t.Error("the plugin is not named Identity")
	}
}
