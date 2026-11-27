// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package zoomeye

import (
	"testing"

	"github.com/owasp-amass/amass/v5/config"
)

func TestRequest(t *testing.T) {
	if r := request("iconhash:-123", &config.Credentials{Username: "u"}); r != nil {
		t.Errorf("a request was built without an API key: %+v", r)
	}
	r := request("iconhash:-123", &config.Credentials{Apikey: "k1"})
	if r == nil {
		t.Fatal("no request")
	}
	if want := searchURL + "?query=iconhash%3A-123"; r.URL != want {
		t.Errorf("URL = %q, want %q", r.URL, want)
	}
	if got := r.Header["API-KEY"]; len(got) != 1 || got[0] != "k1" {
		t.Errorf("API-KEY = %q", got)
	}
	if NewZoomEye().Name() != "ZoomEye" {
		t.Error("the plugin is not named ZoomEye")
	}
}
