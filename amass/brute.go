// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/miekg/dns"
)

// BruteForceQueryTypes contains the DNS record types that service queries for.
var BruteForceQueryTypes = []string{
	"CNAME",
	"A",
	"AAAA",
}

// BruteForceService is the Service that handles all brute force name generation
// within the architecture.
type BruteForceService struct {
	core.BaseService

	metrics    *core.MetricsCollector
	totalLock  sync.RWMutex
	totalNames int
	curIdx     int

	filter *utils.StringFilter
}

// NewBruteForceService returns he object initialized, but not yet started.
func NewBruteForceService(config *core.Config, bus *core.EventBus) *BruteForceService {
	bfs := &BruteForceService{filter: utils.NewStringFilter()}

	bfs.BaseService = *core.NewBaseService(bfs, "Brute Forcing", config, bus)
	return bfs
}

// OnStart implements the Service interface.
func (bfs *BruteForceService) OnStart() error {
	bfs.BaseService.OnStart()

	bfs.metrics = core.NewMetricsCollector(bfs)
	bfs.metrics.NamesRemainingCallback(bfs.namesRemaining)

	if bfs.Config().BruteForcing {
		if bfs.Config().Recursive {
			if bfs.Config().MinForRecursive == 0 {
				bfs.Bus().Subscribe(core.NameResolvedTopic, bfs.SendDNSRequest)
			} else {
				bfs.Bus().Subscribe(core.NewSubdomainTopic, bfs.NewSubdomain)
			}
		}
	}
	go bfs.processRequests()
	return nil
}

// OnLowNumberOfNames implements the Service interface.
func (bfs *BruteForceService) OnLowNumberOfNames() error {
	if !bfs.Config().BruteForcing {
		return nil
	}

	domains := bfs.Config().Domains()
	if len(domains) <= bfs.curIdx {
		return nil
	}

	domain := domains[bfs.curIdx]
	go bfs.performBruteForcing(domain, domain)
	bfs.curIdx++
	return nil
}

// OnStop implements the Service interface.
func (bfs *BruteForceService) OnStop() error {
	bfs.metrics.Stop()
	return nil
}

func (bfs *BruteForceService) processRequests() {
	for {
		select {
		case <-bfs.PauseChan():
			<-bfs.ResumeChan()
		case <-bfs.Quit():
			return
		case req := <-bfs.DNSRequestChan():
			if bfs.Config().Recursive && bfs.Config().MinForRecursive == 0 && bfs.goodRequest(req) {
				go bfs.performBruteForcing(req.Name, req.Domain)
			}
		case <-bfs.AddrRequestChan():
		case <-bfs.ASNRequestChan():
		case <-bfs.WhoisRequestChan():
		}
	}
}

func (bfs *BruteForceService) goodRequest(req *core.DNSRequest) bool {
	if !bfs.Config().IsDomainInScope(req.Name) {
		return false
	}

	if len(req.Records) == 0 {
		return true
	}

	var ok bool
	for _, r := range req.Records {
		t := uint16(r.Type)

		if t == dns.TypeA || t == dns.TypeAAAA {
			ok = true
			break
		}
	}
	return ok
}

// NewSubdomain is called by the Name Service when proper subdomains are discovered.
func (bfs *BruteForceService) NewSubdomain(req *core.DNSRequest, times int) {
	if times == bfs.Config().MinForRecursive {
		go bfs.performBruteForcing(req.Name, req.Domain)
	}
}

func (bfs *BruteForceService) performBruteForcing(subdomain, domain string) {
	subdomain = strings.ToLower(subdomain)
	domain = strings.ToLower(domain)
	req := &core.DNSRequest{
		Name:   subdomain,
		Domain: domain,
	}
	if subdomain == "" || domain == "" || bfs.filter.Duplicate(subdomain) ||
		GetWildcardType(req) == WildcardTypeDynamic {
		return
	}

	bfs.totalLock.Lock()
	bfs.totalNames += len(bfs.Config().Wordlist)
	bfs.totalLock.Unlock()

	var idx int
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-bfs.Quit():
			return
		case <-t.C:
			bfs.SetActive()
		default:
			if idx >= len(bfs.Config().Wordlist) {
				return
			}
			bfs.Config().SemMaxDNSQueries.Acquire(1)
			word := strings.ToLower(bfs.Config().Wordlist[idx])
			go bfs.bruteForceResolution(word, subdomain, domain)
			idx++
		}
	}
}

func (bfs *BruteForceService) bruteForceResolution(word, sub, domain string) {
	defer bfs.SetActive()
	defer bfs.decTotalNames()
	defer bfs.Config().SemMaxDNSQueries.Release(1)

	if word == "" || sub == "" || domain == "" {
		return
	}

	name := word + "." + sub
	var answers []core.DNSAnswer
	for _, t := range BruteForceQueryTypes {
		if a, err := core.Resolve(name, t, core.PriorityLow); err == nil {
			answers = append(answers, a...)
			// Do not continue if a CNAME was discovered
			if t == "CNAME" {
				bfs.metrics.QueryTime(time.Now())
				break
			}
		}
		bfs.metrics.QueryTime(time.Now())
		bfs.SetActive()
	}
	if len(answers) == 0 {
		return
	}

	req := &core.DNSRequest{
		Name:    name,
		Domain:  domain,
		Records: answers,
		Tag:     core.BRUTE,
		Source:  bfs.String(),
	}

	if MatchesWildcard(req) {
		return
	}

	// Check if this passes the enumeration network contraints
	var records []core.DNSAnswer
	for _, ans := range req.Records {
		if ans.Type == 1 || ans.Type == 28 {
			if !bfs.Config().IsAddressInScope(ans.Data) {
				continue
			}
		}
		records = append(records, ans)
	}
	if len(records) == 0 {
		return
	}
	req.Records = records

	bfs.Bus().Publish(core.NameResolvedTopic, req)
}

// Stats implements the Service interface.
func (bfs *BruteForceService) Stats() *core.ServiceStats {
	return bfs.metrics.Stats()
}

func (bfs *BruteForceService) namesRemaining() int {
	bfs.totalLock.RLock()
	defer bfs.totalLock.RUnlock()

	return bfs.totalNames
}

func (bfs *BruteForceService) decTotalNames() {
	bfs.totalLock.Lock()
	defer bfs.totalLock.Unlock()

	bfs.totalNames--
}
