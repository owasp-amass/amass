// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/utils"
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
	BaseService

	metrics    *MetricsCollector
	totalLock  sync.RWMutex
	totalNames int
	curIdx     int

	filter *utils.StringFilter
}

// NewBruteForceService returns he object initialized, but not yet started.
func NewBruteForceService(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *BruteForceService {
	bfs := &BruteForceService{filter: utils.NewStringFilter()}

	bfs.BaseService = *NewBaseService(bfs, "Brute Forcing", cfg, bus, pool)
	return bfs
}

// OnStart implements the Service interface.
func (bfs *BruteForceService) OnStart() error {
	bfs.BaseService.OnStart()

	bfs.metrics = NewMetricsCollector(bfs)
	bfs.metrics.NamesRemainingCallback(bfs.namesRemaining)

	if bfs.Config().BruteForcing {
		if bfs.Config().Recursive {
			if bfs.Config().MinForRecursive == 0 {
				bfs.Bus().Subscribe(requests.NameResolvedTopic, bfs.SendDNSRequest)
			} else {
				bfs.Bus().Subscribe(requests.NewSubdomainTopic, bfs.NewSubdomain)
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

func (bfs *BruteForceService) goodRequest(req *requests.DNSRequest) bool {
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
func (bfs *BruteForceService) NewSubdomain(req *requests.DNSRequest, times int) {
	if times == bfs.Config().MinForRecursive {
		go bfs.performBruteForcing(req.Name, req.Domain)
	}
}

func (bfs *BruteForceService) performBruteForcing(subdomain, domain string) {
	subdomain = strings.ToLower(subdomain)
	domain = strings.ToLower(domain)
	req := &requests.DNSRequest{
		Name:   subdomain,
		Domain: domain,
	}
	if subdomain == "" || domain == "" || bfs.filter.Duplicate(subdomain) ||
		bfs.Pool().GetWildcardType(req) == resolvers.WildcardTypeDynamic {
		return
	}
	wordlist := bfs.Config().Wordlist.ToSlice()

	bfs.totalLock.Lock()
	bfs.totalNames += len(wordlist)
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
			if idx >= len(wordlist) {
				return
			}
			bfs.Config().SemMaxDNSQueries.Acquire(1)
			word := strings.ToLower(wordlist[idx])
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
	var answers []requests.DNSAnswer
	for _, t := range BruteForceQueryTypes {
		if a, err := bfs.Pool().Resolve(name, t, resolvers.PriorityLow); err == nil {
			answers = append(answers, a...)
			// Do not continue if a CNAME was discovered
			if t == "CNAME" {
				bfs.metrics.QueryTime(time.Now())
				break
			}
		} else {
			bfs.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %v", bfs.String(), err))
		}
		bfs.metrics.QueryTime(time.Now())
		bfs.SetActive()
	}
	if len(answers) == 0 {
		return
	}

	req := &requests.DNSRequest{
		Name:    name,
		Domain:  domain,
		Records: answers,
		Tag:     requests.BRUTE,
		Source:  bfs.String(),
	}

	if bfs.Pool().MatchesWildcard(req) {
		return
	}

	// Check if this passes the enumeration network contraints
	var records []requests.DNSAnswer
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

	bfs.Bus().Publish(requests.NameResolvedTopic, req)
}

// Stats implements the Service interface.
func (bfs *BruteForceService) Stats() *ServiceStats {
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
