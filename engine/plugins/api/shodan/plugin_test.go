// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package shodan

import (
	"testing"

	"github.com/owasp-amass/amass/v5/config"
)

func TestRequest(t *testing.T) {
	if r := request("http.favicon.hash:-123", &config.Credentials{Username: "u"}); r != nil {
		t.Errorf("a request was built without an API key: %+v", r)
	}
	r := request("http.favicon.hash:-123", &config.Credentials{Apikey: "k&y"})
	if r == nil {
		t.Fatal("no request")
	}
	if want := searchURL + "?key=k%26y&query=http.favicon.hash%3A-123"; r.URL != want {
		t.Errorf("URL = %q, want %q", r.URL, want)
	}
	if Source.Name != "Shodan" || NewShodan().Name() != "Shodan" {
		t.Error("the plugin is not named Shodan")
	}
}
