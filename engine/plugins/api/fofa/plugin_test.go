// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package fofa

import (
	"testing"

	"github.com/owasp-amass/amass/v5/config"
)

func TestRequest(t *testing.T) {
	for _, cred := range []*config.Credentials{{Username: "me@example.com"}, {Apikey: "k"}} {
		if r := request("aWNvbl9oYXNo", cred); r != nil {
			t.Errorf("a request was built without an email and API key: %+v", cred)
		}
	}
	r := request("aWNvbl9oYXNoPSItMTIzIg==", &config.Credentials{Username: "me@example.com", Apikey: "k1"})
	if r == nil {
		t.Fatal("no request")
	}
	want := searchURL + "?fields=ip,port&size=100&email=me%40example.com&key=k1&qbase64=aWNvbl9oYXNoPSItMTIzIg%3D%3D"
	if r.URL != want {
		t.Errorf("URL = %q, want %q", r.URL, want)
	}
	if NewFOFA().Name() != "FOFA" {
		t.Error("the plugin is not named FOFA")
	}
}
