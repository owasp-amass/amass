// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dns

import (
	"context"
	"math/rand"
	"net"
	"strings"

	"github.com/OWASP/Amass/amass/internal/utils"
)

var (
	// Public & free DNS servers
	PublicResolvers = []string{
		"1.1.1.1:53",        // Cloudflare
		"8.8.8.8:53",        // Google
		"64.6.64.6:53",      // Verisign
		"208.67.222.222:53", // OpenDNS Home
		"77.88.8.8:53",      // Yandex.DNS
		"74.82.42.42:53",    // Hurricane Electric
		"1.0.0.1:53",        // Cloudflare Secondary
		"8.8.4.4:53",        // Google Secondary
		"208.67.220.220:53", // OpenDNS Home Secondary
		"77.88.8.1:53",      // Yandex.DNS Secondary
		// The following servers have shown to be unreliable
		//"64.6.65.6:53",      // Verisign Secondary
		//"9.9.9.9:53",         // Quad9
		//"149.112.112.112:53", // Quad9 Secondary
		//"84.200.69.80:53",    // DNS.WATCH
		//"84.200.70.40:53",    // DNS.WATCH Secondary
		//"8.26.56.26:53",      // Comodo Secure DNS
		//"8.20.247.20:53",     // Comodo Secure DNS Secondary
		//"195.46.39.39:53",    // SafeDNS
		//"195.46.39.40:53",    // SafeDNS Secondary
		//"69.195.152.204:53",  // OpenNIC
		//"216.146.35.35:53",   // Dyn
		//"216.146.36.36:53",   // Dyn Secondary
		//"37.235.1.174:53",   // FreeDNS
		//"37.235.1.177:53",   // FreeDNS Secondary
		//"156.154.70.1:53",    // Neustar
		//"156.154.71.1:53",   // Neustar Secondary
		//"91.239.100.100:53", // UncensoredDNS
		//"89.233.43.71:53",   // UncensoredDNS Secondary
		// These DNS servers have shown send back fake answers
		//"198.101.242.72:53", // Alternate DNS
		//"23.253.163.53:53",  // Alternate DNS Secondary
	}

	CustomResolvers = []string{}
)

// NextResolverAddress - Requests the next server
func NextResolverAddress() string {
	resolvers := PublicResolvers
	if len(CustomResolvers) > 0 {
		resolvers = CustomResolvers
	}

	rnd := rand.Int()
	idx := rnd % len(resolvers)

	return resolvers[idx]
}

func SetCustomResolvers(resolvers []string) {
	for _, r := range resolvers {
		addr := r

		parts := strings.Split(addr, ":")
		if len(parts) == 1 && parts[0] == addr {
			addr += ":53"
		}

		CustomResolvers = utils.UniqueAppend(CustomResolvers, addr)
	}
}

func DNSDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{}

	return d.DialContext(ctx, network, NextResolverAddress())
}

func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{
		// Override the Go default DNS resolver to prevent leakage
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial:     DNSDialContext,
		},
	}
	return d.DialContext(ctx, network, address)
}
