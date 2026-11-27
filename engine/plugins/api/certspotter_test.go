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

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"golang.org/x/time/rate"
)

// apiSession is a plugin-test session scoped to example.com.
func apiSession(t *testing.T) *plugintest.Session {
	t.Helper()

	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Scope().AddDomain("example.com")
	return sess
}

func TestParseCertSpotter(t *testing.T) {
	body := `[{"id":"1","dns_names":["www.example.com","*.example.com"]},` +
		`{"id":"2","dns_names":["mail.example.com"]}]`

	names, last := parseCertSpotter([]byte(body))
	if last != "2" {
		t.Errorf("last id = %q, want 2", last)
	}
	if want := []string{"www.example.com", "*.example.com", "mail.example.com"}; !slices.Equal(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}

	if names, last := parseCertSpotter([]byte("not json")); names != nil || last != "" {
		t.Errorf("a bad body returned %v %q", names, last)
	}
}

// collect pages until a page adds nothing, keeps only in-scope names, strips
// wildcard labels and deduplicates across pages.
func TestCertSpotterCollect(t *testing.T) {
	page1 := `[{"id":"1","dns_names":["www.example.com","*.example.com"]},` +
		`{"id":"2","dns_names":["mail.example.com","out.notexample.org"]}]`
	page2 := `[{"id":"3","dns_names":["dev.example.com","www.example.com"]}]`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("after") {
		case "":
			_, _ = fmt.Fprint(w, page1)
		case "2":
			_, _ = fmt.Fprint(w, page2)
		default:
			_, _ = fmt.Fprint(w, "[]")
		}
	}))
	t.Cleanup(srv.Close)

	c := &certSpotter{name: "CertSpotter", url: srv.URL,
		rlimit: rate.NewLimiter(rate.Inf, 1), source: &et.Source{Name: "CertSpotter"}}

	got := c.collect(&et.Event{Session: apiSession(t)}, "example.com")
	slices.Sort(got)
	want := []string{"dev.example.com", "example.com", "mail.example.com", "www.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("collect = %v, want %v", got, want)
	}
}
