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

// BruteForceService is the Service that handles all brute force name generation
// within the architecture. This is achieved by watching all the NEWSUB events.
type BruteForceService struct {
	core.BaseService

	filter *utils.StringFilter
}

// NewBruteForceService returns he object initialized, but not yet started.
func NewBruteForceService(config *core.Config, bus *core.EventBus) *BruteForceService {
	bfs := &BruteForceService{filter: utils.NewStringFilter()}

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
	}
	go bfs.processRequests()
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
	if !bfs.Config().BruteForcing {
		return false
	}

	if !bfs.Config().IsDomainInScope(req.Name) {
		return false
	}

	bfs.SetActive()

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

func (bfs *BruteForceService) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range bfs.Config().Domains() {
		bfs.performBruteForcing(domain, domain)
	}
}

// NewSubdomain is called by the Name Service when proper subdomains are discovered.
func (bfs *BruteForceService) NewSubdomain(req *core.Request, times int) {
	if times >= bfs.Config().MinForRecursive {
		bfs.SendRequest(req)
	}
}

func (bfs *BruteForceService) performBruteForcing(subdomain, domain string) {
	if bfs.filter.Duplicate(subdomain) {
		return
	}

	bfs.SetActive()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	fire := time.NewTicker(100 * time.Microsecond)
	defer fire.Stop()
	for _, word := range bfs.Config().Wordlist {
		select {
		case <-bfs.Quit():
			return
		case <-t.C:
			bfs.SetActive()
		case <-fire.C:
			bfs.Bus().Publish(core.NewNameTopic, &core.Request{
				Name:   strings.ToLower(word + "." + subdomain),
				Domain: domain,
				Tag:    core.BRUTE,
				Source: bfs.String(),
			})
		}
	}
}
