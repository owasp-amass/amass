// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strings"
	"time"

	"github.com/caffix/recon"
)

type domainRequest struct {
	Subdomain string
	Result    chan string
}

// Requests are sent here to check the root domain of a subdomain name
var domainReqs chan *domainRequest

func init() {
	domainReqs = make(chan *domainRequest, 50)
	go processSubToRootDomain()
}

func SubdomainToDomain(name string) string {
	result := make(chan string, 2)

	domainReqs <- &domainRequest{
		Subdomain: name,
		Result:    result,
	}
	return <-result
}

func processSubToRootDomain() {
	var queue []*domainRequest

	cache := make(map[string]struct{})

	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case req := <-domainReqs:
			queue = append(queue, req)
		case <-t.C:
			var next *domainRequest

			if len(queue) == 1 {
				next = queue[0]
				queue = []*domainRequest{}
			} else if len(queue) > 1 {
				next = queue[0]
				queue = queue[1:]
			}

			if next != nil {
				next.Result <- rootDomainLookup(next.Subdomain, cache)
			}
		}
	}
}

func rootDomainLookup(name string, cache map[string]struct{}) string {
	var domain string

	// Obtain all parts of the subdomain name
	labels := strings.Split(strings.TrimSpace(name), ".")
	// Check the cache for all parts of the name
	for i := len(labels) - 2; i >= 0; i-- {
		sub := strings.Join(labels[i:], ".")

		if _, found := cache[sub]; found {
			domain = sub
			break
		}
	}
	// If the root domain was in the cache, return it now
	if domain != "" {
		return domain
	}
	// Check the DNS for all parts of the name
	for i := len(labels) - 2; i >= 0; i-- {
		sub := strings.Join(labels[i:], ".")

		if checkDNSforDomain(sub) {
			cache[sub] = struct{}{}
			domain = sub
			break
		}
	}
	return domain
}

func checkDNSforDomain(domain string) bool {
	server := Resolvers.NextNameserver()

	// Check DNS for CNAME, A or AAAA records
	_, err := recon.ResolveDNS(domain, server, "CNAME")
	if err == nil {
		return true
	}
	_, err = recon.ResolveDNS(domain, server, "A")
	if err == nil {
		return true
	}
	_, err = recon.ResolveDNS(domain, server, "AAAA")
	if err == nil {
		return true
	}
	return false
}
