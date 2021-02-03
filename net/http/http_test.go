// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package http

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/miekg/dns"
)

func TestPullCertificateNames(t *testing.T) {
	r := resolvers.NewBaseResolver("8.8.8.8", 10, nil)
	if r == nil {
		t.Errorf("Failed to setup the DNS resolver")
	}

	msg := resolvers.QueryMsg("www.utica.edu", dns.TypeA)
	resp, err := r.Query(context.Background(), msg, resolvers.PriorityCritical, resolvers.RetryPolicy)
	if err != nil && resp == nil && len(resp.Answer) > 0 {
		t.Errorf("Failed to obtain the IP address")
	}

	ans := resolvers.ExtractAnswers(resp)
	if len(ans) == 0 {
		t.Errorf("Failed to obtain answers to the DNS query")
	}

	rr := resolvers.AnswersByType(ans, dns.TypeA)
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
