// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strings"
	"time"

	"github.com/miekg/dns"
)

// BruteForceService is the Service that handles all brute force name generation
// within the architecture. This is achieved by watching all the NEWSUB events.
type BruteForceService struct {
	BaseService
}

// NewBruteForceService returns he object initialized, but not yet started.
func NewBruteForceService(e *Enumeration) *BruteForceService {
	bfs := new(BruteForceService)

	bfs.BaseService = *NewBaseService(e, "Brute Forcing", bfs)
	return bfs
}

// OnStart implements the Service interface
func (bfs *BruteForceService) OnStart() error {
	bfs.BaseService.OnStart()

	if bfs.Enum().Config.BruteForcing {
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

func (bfs *BruteForceService) goodRequest(req *Request) bool {
	if !bfs.Enum().Config.BruteForcing {
		return false
	}

	if !bfs.Enum().Config.IsDomainInScope(req.Name) {
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
	for _, domain := range bfs.Enum().Config.Domains() {
		bfs.SendRequest(&Request{
			Name:   domain,
			Domain: domain,
		})
	}
}

// NewSubdomain is called by the Name Service when proper subdomains are discovered.
func (bfs *BruteForceService) NewSubdomain(req *Request, times int) {
	if times == bfs.Enum().Config.MinForRecursive {
		bfs.SendRequest(req)
	}
}

func (bfs *BruteForceService) performBruteForcing(subdomain, root string) {
	t := time.NewTicker(time.Second)
	defer t.Stop()

	bfs.SetActive()
	for _, word := range bfs.Enum().Config.Wordlist {
		select {
		case <-t.C:
			bfs.SetActive()
		case <-bfs.Quit():
			return
		default:
			bfs.Enum().NewNameEvent(&Request{
				Name:   strings.ToLower(word + "." + subdomain),
				Domain: root,
				Tag:    BRUTE,
				Source: bfs.String(),
			})
		}
	}
}
