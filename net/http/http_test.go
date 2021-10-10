// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package http

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/caffix/resolve"
	"github.com/miekg/dns"
)

func TestPullCertificateNames(t *testing.T) {
	r := resolve.NewBaseResolver("8.8.8.8", 10, nil)
	if r == nil {
		t.Errorf("Failed to setup the DNS resolver")
	}

	msg := resolve.QueryMsg("www.utica.edu", dns.TypeA)
	resp, err := r.Query(context.Background(), msg, resolve.PriorityCritical, resolve.RetryPolicy)
	if err != nil && resp == nil && len(resp.Answer) > 0 {
		t.Errorf("Failed to obtain the IP address")
	}

	ans := resolve.ExtractAnswers(resp)
	if len(ans) == 0 {
		t.Errorf("Failed to obtain answers to the DNS query")
	}

	rr := resolve.AnswersByType(ans, dns.TypeA)
	if len(rr) == 0 {
		t.Errorf("Failed to obtain the answers of the correct type")
	}

	ip := net.ParseIP(strings.TrimSpace(rr[0].Data))
	if ip == nil {
		t.Errorf("Failed to extract a valid IP address from the DNS response")
	}

	if names := PullCertificateNames(context.Background(), ip.String(), []int{443}); len(names) == 0 {
		t.Errorf("Failed to obtain names from a certificate from address %s", ip.String())
	}
}

func TestCheckCookie(t *testing.T) {
	type args struct {
		urlString  string
		cookieName string
	}
	tests := []struct {
		name string
		init func()
		args args
		want bool
	}{
		{
			name: "basic-success",
			init: func() {
				sampleURL, err := url.Parse("http://owasp.org")
				if err != nil {
					t.Errorf("CheckCookie() parse error: got error = %v", err)
				}

				cookies := []*http.Cookie{{Name: "cookie1", Value: "sample cookie value"}}
				DefaultClient.Jar.SetCookies(sampleURL, cookies)

			},
			args: args{
				urlString:  "https://owasp.org",
				cookieName: "cookie1",
			},
			want: true,
		},
		{
			name: "basic-failure",
			init: func() {},
			args: args{
				urlString:  "http://domain.local",
				cookieName: "cookie2",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.init()
			if got := CheckCookie(tt.args.urlString, tt.args.cookieName); got != tt.want {
				t.Errorf("CheckCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}
