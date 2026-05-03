// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/caffix/stringset"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
)

func TestRequestWebPage(t *testing.T) {
	name := "caffix"
	pass := "OWASP"
	hkey := "OWASP-Leader"
	post := "Test Body"
	succ := "Success"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if username, password, ok := r.BasicAuth(); !ok || username != name || password != pass {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, "Authentication Failed")
			return
		}
		if val := r.Header.Get(hkey); val != name {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, "Header value was missing")
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, "Method was not POST")
			return
		}
		if in, err := io.ReadAll(r.Body); err != nil || string(in) != post {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, "POST body did not match")
			return
		}
		_, _ = fmt.Fprint(w, succ)
	}))
	defer ts.Close()

	resp, err := RequestWebPage(context.TODO(), DefaultClient, &Request{
		URL:  ts.URL,
		Auth: &BasicAuth{name, pass},
	})
	if err == nil && (resp.StatusCode == 200 || resp.Body == succ) {
		t.Error("Failed to detect the bad request")
	}

	resp, err = RequestWebPage(context.TODO(), DefaultClient, &Request{
		URL:    ts.URL,
		Method: "POST",
		Header: Header{hkey: []string{name}},
		Body:   post,
		Auth:   &BasicAuth{name, pass},
	})
	if err != nil || resp.StatusCode != 200 || resp.Body != succ {
		t.Error(resp.Status + ": " + resp.Body)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resp, err = RequestWebPage(ctx, DefaultClient, &Request{URL: ts.URL})
	if err == nil || resp != nil {
		t.Error("Failed to detect the expired context")
	}
}

func TestCrawl(t *testing.T) {
	re, err := regexp.Compile(amassdns.AnySubdomainRegexString())
	if err != nil {
		return
	}

	tests := []struct {
		name  string
		depth int
		want  []string
	}{
		{
			name:  "first page only",
			depth: 1,
			want:  []string{"example.com", "127.0.0.1"},
		},
		{
			name:  "first and second page",
			depth: 2,
			want: []string{"example.com", "127.0.0.1", "xml.owasp.org",
				"www.owasp.org", "www.example.com", "sub.example.com", "www.google.com"},
		},
		{
			name:  "all of the pages",
			depth: 0,
			want: []string{"example.com", "127.0.0.1", "xml.owasp.org",
				"www.owasp.org", "www.example.com", "sub.example.com",
				"www.google.com", "owasp.org", "img.owasp.org",
				"media.owasp.org", "static.owasp.org", "blogs.oracle.com"},
		},
	}

	ts := httptest.NewServer(http.FileServer(http.Dir("./static")))
	defer ts.Close()

	for _, test := range tests {
		got := stringset.New()
		defer got.Close()
		set := stringset.New(test.want...)
		defer set.Close()

		err := Crawl(context.Background(), ts.URL, []string{"127.0.0.1"}, test.depth, func(req *Request, resp *Response) {
			if u, err := url.Parse(req.URL); err == nil {
				got.Insert(CleanName(u.Hostname()))
			}
			got.InsertMany(re.FindAllString(resp.Body, -1)...)
		})
		if err != nil {
			t.Errorf("Failed to crawl the static web content: %s: %v", test.name, err)
			continue
		}

		set.Subtract(got)
		if set.Len() != 0 {
			t.Errorf("Test %s with max %d failed to discover the following names: %v\n", test.name, test.depth, set.Slice())
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = Crawl(ctx, ts.URL, []string{"127.0.0.1"}, 0, func(req *Request, resp *Response) {})
	if err != nil && err.Error() != "the context expired during the crawl of "+ts.URL {
		t.Error("Failed to catch the expired context during the crawl")
	}

	err = Crawl(ctx, ts.URL, []string{"127.0.0.1"}, 0, func(req *Request, resp *Response) {})
	if err != nil && err.Error() != "the context expired" {
		t.Error("Failed to catch the expired context before the crawl")
	}
}

func TestCleanName(t *testing.T) {
	tests := []struct {
		data string
		want string
	}{
		{
			data: "3aowasp.org",
			want: "owasp.org",
		},
		{
			data: "http://www.owasp.org/index.html",
			want: "www.owasp.org",
		},
		{
			data: "-Sub.OWASP.org.",
			want: "sub.owasp.org",
		},
		{
			data: "http://www.owasp.org/index.html",
			want: "www.owasp.org",
		},
		{
			data: "http://blackhat2018.owasp.org/index.html",
			want: "blackhat2018.owasp.org",
		},
	}

	for _, test := range tests {
		if got := CleanName(test.data); got != test.want {
			t.Errorf("Got: %s, Want: %s", got, test.want)
		}
	}
}
