// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/miekg/dns"
)

// BruteForceQueryTypes contains the DNS record types that service queries for.
var BruteForceQueryTypes = []string{
	"TXT",
	"CNAME",
	"A",
	"AAAA",
}

// BruteForceService is the Service that handles all brute force name generation
// within the architecture.
type BruteForceService struct {
	core.BaseService

	max    utils.Semaphore
	filter *utils.StringFilter
}

// NewBruteForceService returns he object initialized, but not yet started.
func NewBruteForceService(config *core.Config, bus *core.EventBus) *BruteForceService {
	num := (len(resolvers) * 100) / len(BruteForceQueryTypes)
	bfs := &BruteForceService{
		max:    utils.NewSimpleSemaphore(num),
		filter: utils.NewStringFilter(),
	}

	bfs.BaseService = *core.NewBaseService(bfs, "Brute Forcing", config, bus)
	return bfs
}

// OnStart implements the Service interface
func (bfs *BruteForceService) OnStart() error {
	bfs.BaseService.OnStart()

	if bfs.Config().BruteForcing {
		if bfs.Config().Recursive {
			if bfs.Config().MinForRecursive == 0 {
				bfs.Bus().Subscribe(core.NameResolvedTopic, bfs.SendRequest)
			} else {
				bfs.Bus().Subscribe(core.NewSubdomainTopic, bfs.NewSubdomain)
			}
		}
		go bfs.startRootDomains()
		go bfs.processRequests()
	}
	return nil
}

func (bfs *BruteForceService) processRequests() {
	for {
		select {
		case <-bfs.PauseChan():
			<-bfs.ResumeChan()
		case <-bfs.Quit():
			return
		case req := <-bfs.RequestChan():
			if bfs.goodRequest(req) {
				bfs.performBruteForcing(req.Name, req.Domain)
			}
		}
	}
}

func (bfs *BruteForceService) goodRequest(req *core.Request) bool {
	if !bfs.Config().IsDomainInScope(req.Name) {
		return false
	}

	var ok bool
	bfs.SetActive()
	for _, r := range req.Records {
		t := uint16(r.Type)

		if t == dns.TypeA || t == dns.TypeAAAA {
			ok = true
			break
		}
	}
	return ok
}

func (bfs *BruteForceService) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range bfs.Config().Domains() {
		bfs.performBruteForcing(domain, domain)
	}
}

// NewSubdomain is called by the Name Service when proper subdomains are discovered.
func (bfs *BruteForceService) NewSubdomain(req *core.Request, times int) {
	if times == bfs.Config().MinForRecursive {
		bfs.SendRequest(req)
	}
}

func (bfs *BruteForceService) performBruteForcing(subdomain, domain string) {
	subdomain = strings.ToLower(subdomain)
	domain = strings.ToLower(domain)
	req := &core.Request{
		Name:   subdomain,
		Domain: domain,
	}
	if subdomain == "" || domain == "" || bfs.filter.Duplicate(subdomain) ||
		GetWildcardType(req) == WildcardTypeDynamic {
		return
	}

	curIdx := 0
	maxIdx := 7
	delays := []int{10, 25, 50, 75, 100, 150, 250, 500}
	bfs.SetActive()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for _, word := range bfs.Config().Wordlist {
		select {
		case <-bfs.Quit():
			return
		case <-t.C:
			bfs.SetActive()
		default:
			if !bfs.max.TryAcquire(1) {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue
			}
			curIdx = 0
			if word != "" {
				name := strings.ToLower(word + "." + subdomain)
				go bfs.bruteForceResolution(name, subdomain, domain)
			}
		}
	}
}

func (bfs *BruteForceService) bruteForceResolution(name, sub, domain string) {
	defer bfs.max.Release(1)
	defer bfs.SetActive()

	if name == "" || domain == "" {
		return
	}

	var answers []core.DNSAnswer
	for _, t := range BruteForceQueryTypes {
		if a, err := Resolve(name, t); err == nil {
			answers = append(answers, a...)
			// Do not continue if a CNAME was discovered
			if t == "CNAME" {
				break
			}
		}
	}

	req := &core.Request{
		Name:   name,
		Domain: domain,
	}
	if len(answers) == 0 || MatchesWildcard(req) {
		return
	}

	bfs.Bus().Publish(core.NameResolvedTopic, &core.Request{
		Name:    name,
		Domain:  domain,
		Records: answers,
		Tag:     core.BRUTE,
		Source:  bfs.String(),
	})
}
