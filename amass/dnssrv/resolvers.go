// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dnssrv

import (
	"bufio"
	"context"
	"math/rand"
	"net"
	"strings"

	"github.com/OWASP/Amass/amass/utils"
	"golang.org/x/sync/semaphore"
)

const (
	defaultNumOpenFiles int64 = 10000
)

var (
	// Public & free DNS servers
	PublicResolvers = []string{
		"1.1.1.1:53",     // Cloudflare
		"8.8.8.8:53",     // Google
		"64.6.64.6:53",   // Verisign
		"77.88.8.8:53",   // Yandex.DNS
		"74.82.42.42:53", // Hurricane Electric
		"1.0.0.1:53",     // Cloudflare Secondary
		"8.8.4.4:53",     // Google Secondary
		"77.88.8.1:53",   // Yandex.DNS Secondary
	}

	CustomResolvers = []string{}

	// Enforces a maximum number of open connections at any given moment
	MaxConnections *semaphore.Weighted
)

func init() {
	// Obtain the proper weight based on file resource limits
	weight := (GetFileLimit() / 10) * 8
	if weight <= 0 {
		weight = defaultNumOpenFiles
	}
	MaxConnections = semaphore.NewWeighted(weight)

	url := "https://raw.githubusercontent.com/OWASP/Amass/master/wordlists/nameservers.txt"
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		return
	}

	PublicResolvers = []string{}
	scanner := bufio.NewScanner(strings.NewReader(page))
	for scanner.Scan() {
		addr := strings.TrimSpace(scanner.Text())

		if err := scanner.Err(); err == nil {
			PublicResolvers = append(PublicResolvers, addr)
		}
	}
}

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

	MaxConnections.Acquire(ctx, 1)
	return d.DialContext(ctx, network, NextResolverAddress())
}

func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial:     DNSDialContext,
		},
	}

	MaxConnections.Acquire(ctx, 1)
	return d.DialContext(ctx, network, address)
}
