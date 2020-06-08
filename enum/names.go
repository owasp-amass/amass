// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"strings"
	"sync"

	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringfilter"
)

var probeNames = []string{
	"www",
	"online",
	"webserver",
	"ns1",
	"mail",
	"smtp",
	"webmail",
	"prod",
	"test",
	"vpn",
	"ftp",
	"ssh",
}

// FQDNManager is the object type for taking in, generating and providing new DNS FQDNs.
type FQDNManager interface {
	// InputName shares a newly discovered FQDN with the NameManager
	InputName(req *requests.DNSRequest)

	// OutputNames requests new FQDNs from the NameManager
	OutputNames(num int) []*requests.DNSRequest

	Stop() error
}

// DomainManager handles the release of new domains names to data sources used in the enumeration.
type DomainManager struct {
	enum   *Enumeration
	queue  *queue.Queue
	filter stringfilter.Filter
}

// NewDomainManager returns an initialized DomainManager.
func NewDomainManager(e *Enumeration) *DomainManager {
	return &DomainManager{
		enum:   e,
		queue:  new(queue.Queue),
		filter: stringfilter.NewStringFilter(),
	}
}

// InputName implements the FQDNManager interface.
func (r *DomainManager) InputName(req *requests.DNSRequest) {
	if req == nil || req.Name == "" || req.Domain == "" {
		return
	}

	if r.filter.Duplicate(req.Domain) {
		return
	}

	r.queue.Append(req)
}

// OutputNames implements the FQDNManager interface.
func (r *DomainManager) OutputNames(num int) []*requests.DNSRequest {
	var results []*requests.DNSRequest

	if num <= 0 {
		return results
	}

	element, ok := r.queue.Next()
	if !ok {
		return results
	}

	req := element.(*requests.DNSRequest)
	results = append(results, req)

	r.enum.srcsLock.Lock()
	// Release the new domain name to all the data sources
	for _, src := range r.enum.Sys.DataSources() {
		if !r.enum.srcs.Has(src.String()) {
			continue
		}

		src.DNSRequest(r.enum.ctx, &requests.DNSRequest{
			Name:   req.Domain,
			Domain: req.Domain,
			Tag:    requests.DNS,
			Source: "DNS",
		})
	}
	r.enum.srcsLock.Unlock()

	return results
}

// Stop implements the FQDNManager interface.
func (r *DomainManager) Stop() error {
	r.queue = new(queue.Queue)
	r.filter = stringfilter.NewStringFilter()
	return nil
}

// SubdomainManager handles newly discovered proper subdomain names in the enumeration.
type SubdomainManager struct {
	sync.Mutex
	enum       *Enumeration
	queue      *queue.Queue
	subdomains map[string]int
}

// NewSubdomainManager returns an initialized SubdomainManager.
func NewSubdomainManager(e *Enumeration) *SubdomainManager {
	return &SubdomainManager{
		enum:       e,
		queue:      new(queue.Queue),
		subdomains: make(map[string]int),
	}
}

// InputName implements the FQDNManager interface.
func (r *SubdomainManager) InputName(req *requests.DNSRequest) {
	if req == nil || req.Name == "" || req.Domain == "" {
		return
	}

	// Clean up the newly discovered name and domain
	requests.SanitizeDNSRequest(req)

	// Send every resolved name and associated DNS records to the data manager
	r.enum.dataMgr.DNSRequest(r.enum.ctx, req)

	if !r.enum.Config.IsDomainInScope(req.Name) {
		return
	}

	// Keep track of all domains and proper subdomains discovered
	r.checkSubdomain(req)

	// Send out some probe requests to help cause recursive brute forcing
	if r.enum.Config.BruteForcing && r.enum.Config.Recursive && r.enum.Config.MinForRecursive > 0 {
		for _, probe := range probeNames {
			r.queue.Append(&requests.DNSRequest{
				Name:   probe + "." + req.Name,
				Domain: req.Domain,
				Tag:    requests.BRUTE,
				Source: "Enum Probes",
			})
		}
	}

	// Queue the resolved name for future brute forcing
	if r.enum.Config.BruteForcing && r.enum.Config.Recursive && r.enum.Config.MinForRecursive == 0 {
		// Do not send in the resolved root domain names
		if len(strings.Split(req.Name, ".")) != len(strings.Split(req.Domain, ".")) {
			r.enum.bruteMgr.InputName(req)
		}
	}

	labels := strings.Split(req.Name, ".")
	// Do not further evaluate service subdomains
	if labels[1] == "_tcp" || labels[1] == "_udp" || labels[1] == "_tls" {
		return
	}

	r.enum.srcsLock.Lock()
	defer r.enum.srcsLock.Unlock()
	// Alert all data sources to the newly discovered subdomain name
	for _, srv := range r.enum.Sys.DataSources() {
		if r.enum.srcs.Has(srv.String()) {
			srv.SubdomainDiscovered(r.enum.ctx, req, 1)
		}
	}
}

// OutputNames implements the FQDNManager interface.
func (r *SubdomainManager) OutputNames(num int) []*requests.DNSRequest {
	var results []*requests.DNSRequest

	for i := 0; ; i++ {
		if num >= 0 && i >= num {
			break
		}

		element, ok := r.queue.Next()
		if !ok {
			break
		}

		req := element.(*requests.DNSRequest)
		results = append(results, req)
	}

	return results
}

// Stop implements the FQDNManager interface.
func (r *SubdomainManager) Stop() error {
	r.queue = new(queue.Queue)
	return nil
}

func (r *SubdomainManager) checkSubdomain(req *requests.DNSRequest) {
	labels := strings.Split(req.Name, ".")
	num := len(labels)
	// Is this large enough to consider further?
	if num < 2 {
		return
	}
	// It cannot have fewer labels than the root domain name
	if num-1 < len(strings.Split(req.Domain, ".")) {
		return
	}
	// Do not further evaluate service subdomains
	if labels[1] == "_tcp" || labels[1] == "_udp" || labels[1] == "_tls" {
		return
	}

	sub := strings.TrimSpace(strings.Join(labels[1:], "."))
	// CNAMEs are not a proper subdomain
	if r.enum.Graph.IsCNAMENode(sub) {
		return
	}

	subreq := &requests.DNSRequest{
		Name:   sub,
		Domain: req.Domain,
		Tag:    req.Tag,
		Source: req.Source,
	}
	times := r.timesForSubdomain(sub)

	r.enum.Bus.Publish(requests.SubDiscoveredTopic, eventbus.PriorityHigh, r.enum.ctx, subreq, times)
	// Queue the proper subdomain for future brute forcing
	if r.enum.Config.BruteForcing && r.enum.Config.Recursive &&
		r.enum.Config.MinForRecursive > 0 && r.enum.Config.MinForRecursive == times {
		r.enum.bruteMgr.InputName(subreq)
	}
	// Check if the subdomain should be added to the markov model
	if r.enum.Config.Alterations && r.enum.guessMgr != nil && times == 1 {
		r.enum.guessMgr.AddSubdomain(sub)
	}
}

func (r *SubdomainManager) timesForSubdomain(sub string) int {
	r.Lock()
	defer r.Unlock()

	times, found := r.subdomains[sub]
	if found {
		times++
	} else {
		times = 1
	}

	r.subdomains[sub] = times
	return times
}

// NameManager handles the filtering and release of newly discovered FQDNs in the enumeration.
type NameManager struct {
	enum  *Enumeration
	queue *queue.Queue
}

// NewNameManager returns an initialized NameManager.
func NewNameManager(e *Enumeration) *NameManager {
	return &NameManager{
		enum:  e,
		queue: new(queue.Queue),
	}
}

// InputName implements the FQDNManager interface.
func (r *NameManager) InputName(req *requests.DNSRequest) {
	if req == nil || req.Name == "" || req.Domain == "" {
		return
	}

	// Clean up the newly discovered name and domain
	requests.SanitizeDNSRequest(req)

	r.queue.Append(req)
}

// OutputNames implements the FQDNManager interface.
func (r *NameManager) OutputNames(num int) []*requests.DNSRequest {
	var results []*requests.DNSRequest

	for i := 0; ; i++ {
		if num >= 0 && i >= num {
			break
		}

		element, ok := r.queue.Next()
		if !ok {
			break
		}

		req := element.(*requests.DNSRequest)
		results = append(results, req)
	}

	return results
}

// Stop implements the FQDNManager interface.
func (r *NameManager) Stop() error {
	r.queue = new(queue.Queue)
	return nil
}
