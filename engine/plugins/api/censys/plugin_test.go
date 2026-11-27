// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package censys

import (
	"encoding/base64"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
)

func TestRequest(t *testing.T) {
	for _, cred := range []*config.Credentials{{Username: "id"}, {Secret: "s"}, {Apikey: "k"}} {
		if r := request("services.jarm.fingerprint: abc", cred); r != nil {
			t.Errorf("a request was built without an API ID and secret: %+v", cred)
		}
	}
	r := request("services.jarm.fingerprint: abc", &config.Credentials{Username: "id", Secret: "s"})
	if r == nil {
		t.Fatal("no request")
	}
	if want := searchURL + "?per_page=50&q=services.jarm.fingerprint%3A+abc"; r.URL != want {
		t.Errorf("URL = %q, want %q", r.URL, want)
	}
	if got := r.Header["Authorization"]; len(got) != 1 ||
		got[0] != "Basic "+base64.StdEncoding.EncodeToString([]byte("id:s")) {
		t.Errorf("Authorization = %q", got)
	}
	if NewCensys().Name() != "Censys" {
		t.Error("the plugin is not named Censys")
	}
}
