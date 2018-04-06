// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"context"
	"net"
	"testing"
)

func ResolveDNS(name, server, qtype string) ([]DNSAnswer, error) {
	dc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &net.Dialer{}

		return d.DialContext(ctx, network, server)
	}
	return ResolveDNSWithDialContext(dc, name, qtype)
}

func ReverseDNS(ip, server string) (string, error) {
	dc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &net.Dialer{}

		return d.DialContext(ctx, network, server)
	}
	return ReverseDNSWithDialContext(dc, ip)
}

func TestResolversPublicResolvers(t *testing.T) {
	for _, server := range PublicResolvers {
		a, err := ResolveDNS(testDomain, server, "A")
		if err != nil || len(a) == 0 {
			t.Errorf("%s failed to resolve the A record for %s", server, testDomain)
		}
	}
}
