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

func TestParseColumbus(t *testing.T) {
	got := parseColumbus([]byte(`["www","mail",""]`), "example.com")
	if want := []string{"www.example.com", "mail.example.com", "example.com"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	// A label is lowercased and its stray dots are trimmed.
	if got := parseColumbus([]byte(`[".DEV."]`), "Example.com"); !slices.Equal(got, []string{"dev.example.com"}) {
		t.Errorf("got %v", got)
	}

	if parseColumbus([]byte("nope"), "example.com") != nil {
		t.Error("a bad body did not return nil")
	}
}

func TestColumbusCollect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `["www","dev",""]`)
	}))
	t.Cleanup(srv.Close)

	c := &columbus{name: "Columbus", url: srv.URL + "/",
		rlimit: rate.NewLimiter(rate.Inf, 1), source: &et.Source{Name: "Columbus"}}

	got := c.collect(&et.Event{Session: apiSession(t)}, "example.com")
	slices.Sort(got)
	if want := []string{"dev.example.com", "example.com", "www.example.com"}; !slices.Equal(got, want) {
		t.Errorf("collect = %v, want %v", got, want)
	}
}
