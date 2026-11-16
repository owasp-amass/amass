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

func TestParseThreatMiner(t *testing.T) {
	body := `{"status_code":"200","status_message":"ok","results":["www.example.com","mail.example.com."]}`
	if got := parseThreatMiner([]byte(body)); !slices.Equal(got, []string{"www.example.com", "mail.example.com"}) {
		t.Errorf("got %v", got)
	}

	// A "no results" 404 body carries results as a string, not an array.
	if got := parseThreatMiner([]byte(`{"status_code":"404","results":"No results found."}`)); got != nil {
		t.Errorf("a 404 body returned %v, want nil", got)
	}

	if parseThreatMiner([]byte("nope")) != nil {
		t.Error("a bad body did not return nil")
	}
}

func TestThreatMinerCollect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("rt") != "5" {
			http.Error(w, "unexpected report type", http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprint(w, `{"status_code":"200","results":["www.example.com","bad.notexample.org","mail.example.com"]}`)
	}))
	t.Cleanup(srv.Close)

	tm := &threatMiner{name: "ThreatMiner", url: srv.URL,
		rlimit: rate.NewLimiter(rate.Inf, 1), source: &et.Source{Name: "ThreatMiner"}}

	got := tm.collect(&et.Event{Session: apiSession(t)}, "example.com")
	slices.Sort(got)
	if want := []string{"mail.example.com", "www.example.com"}; !slices.Equal(got, want) {
		t.Errorf("collect = %v, want %v", got, want)
	}
}
