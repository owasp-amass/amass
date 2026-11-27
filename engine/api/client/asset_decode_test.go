// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"io"
	"strings"
	"testing"

	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// Every Open Asset Model type has a constructor that makes that type.
func TestNewAssetCoversTheModel(t *testing.T) {
	for _, atype := range oam.AssetList {
		a, ok := NewAsset(atype)
		if !ok || a == nil || a.AssetType() != atype {
			t.Errorf("NewAsset(%s) = %v, %v", atype, a, ok)
		}
	}
	if _, ok := NewAsset("Domain"); ok {
		t.Error("an unknown type has a constructor")
	}
}

func TestParseAsset(t *testing.T) {
	a, err := ParseAsset("fqdn", []byte(`{"name":"www.example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := a.(*oamdns.FQDN); !ok || f.Name != "www.example.com" {
		t.Errorf("parsed %#v", a)
	}
	if _, err := ParseAsset("FQDN", []byte(`{"name":"x"}`)); err != nil {
		t.Errorf("the type name is compared without case: %v", err)
	}
	if _, err := ParseAsset("domain", []byte(`{"name":"x"}`)); err == nil {
		t.Error("an unknown type was parsed")
	}
	if _, err := ParseAsset("fqdn", []byte(`{"name":`)); err == nil {
		t.Error("malformed JSON was parsed")
	}
}

func TestDecodeAssetsForScopeEndpoint(t *testing.T) {
	body := io.NopCloser(strings.NewReader(`{"data":[{"number":64496},{"number":64497}]}`))
	got, err := DecodeAssetsForScopeEndpoint(oam.AutonomousSystem, body)
	if err != nil || len(got) != 2 {
		t.Fatalf("decoded %v, %v", got, err)
	}
	// each element is its own asset, not one reused variable
	if got[0].(*oamnet.AutonomousSystem).Number != 64496 || got[1].(*oamnet.AutonomousSystem).Number != 64497 {
		t.Errorf("decoded %+v, %+v", got[0], got[1])
	}

	for name, data := range map[string]string{
		"empty": `{"data":[]}`, "malformed": `{"data":[`, "wrong shape": `{"data":[{"number":"x"}]}`,
	} {
		if _, err := DecodeAssetsForScopeEndpoint(oam.AutonomousSystem, io.NopCloser(strings.NewReader(data))); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := DecodeAssetsForScopeEndpoint("Domain", io.NopCloser(strings.NewReader(`{"data":[{}]}`))); err == nil {
		t.Error("an unknown type was decoded")
	}
}
