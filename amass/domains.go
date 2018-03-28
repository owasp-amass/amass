// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strings"
	"time"
)

type DomainRequest struct {
	Subdomain string
	Result    chan string
}

type DomainLookup struct {
	// Requests are sent here to check the root domain of a subdomain name
	Requests chan *DomainRequest

	// The configuration being used by the amass enumeration
	Config *AmassConfig
}

func NewDomainLookup(config *AmassConfig) *DomainLookup {
	dl := &DomainLookup{
		Requests: make(chan *DomainRequest, 50),
		Config:   config,
	}

	go dl.processSubToRootDomain()
	return dl
}

func (dl *DomainLookup) SubdomainToDomain(name string) string {
	result := make(chan string, 2)

	dl.Requests <- &DomainRequest{
		Subdomain: name,
		Result:    result,
	}
	return <-result
}

func (dl *DomainLookup) processSubToRootDomain() {
	var queue []*DomainRequest

	cache := make(map[string]struct{})

	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case req := <-dl.Requests:
			queue = append(queue, req)
		case <-t.C:
			var next *DomainRequest

			if len(queue) == 1 {
				next = queue[0]
				queue = []*DomainRequest{}
			} else if len(queue) > 1 {
				next = queue[0]
				queue = queue[1:]
			}

			if next != nil {
				next.Result <- dl.rootDomainLookup(next.Subdomain, cache)
			}
		}
	}
}

func (dl *DomainLookup) rootDomainLookup(name string, cache map[string]struct{}) string {
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

		if dl.checkDNSforDomain(sub) {
			cache[sub] = struct{}{}
			domain = sub
			break
		}
	}
	return domain
}

func (dl *DomainLookup) checkDNSforDomain(domain string) bool {
	if _, err := dl.Config.dns.Query(domain); err == nil {
		return true
	}
	return false
}
