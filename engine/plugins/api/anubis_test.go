// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"golang.org/x/time/rate"
)

func TestParseAnubis(t *testing.T) {
	got := parseAnubis([]byte(`["WWW.example.com","mail.example.com.",""]`))
	if want := []string{"www.example.com", "mail.example.com"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	if parseAnubis([]byte("nope")) != nil {
		t.Error("a bad body did not return nil")
	}
}

func TestAnubisCollect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `["www.example.com","evil.notexample.org","mail.example.com","www.example.com"]`)
	}))
	t.Cleanup(srv.Close)

	a := &anubis{name: "Anubis", url: srv.URL + "/",
		rlimit: rate.NewLimiter(rate.Inf, 1), source: &et.Source{Name: "Anubis"}}

	got := a.collect(&et.Event{Session: apiSession(t)}, "example.com")
	slices.Sort(got)
	if want := []string{"mail.example.com", "www.example.com"}; !slices.Equal(got, want) {
		t.Errorf("collect = %v, want %v (out-of-scope and duplicates removed)", got, want)
	}
}
