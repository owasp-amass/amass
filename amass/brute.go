// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strings"
	"time"
)

type BruteForceService struct {
	BaseAmassService

	// Subdomains that have been worked on by brute forcing
	subdomains map[string]struct{}
}

func NewBruteForceService(in, out chan *AmassRequest, config *AmassConfig) *BruteForceService {
	bfs := &BruteForceService{subdomains: make(map[string]struct{})}

	bfs.BaseAmassService = *NewBaseAmassService("Brute Forcing Service", config, bfs)

	bfs.input = in
	bfs.output = out
	return bfs
}

func (bfs *BruteForceService) OnStart() error {
	bfs.BaseAmassService.OnStart()

	go bfs.processRequests()
	go bfs.startRootDomains()
	return nil
}

func (bfs *BruteForceService) OnStop() error {
	bfs.BaseAmassService.OnStop()
	return nil
}

func (bfs *BruteForceService) processRequests() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case req := <-bfs.Input():
			go bfs.checkForNewSubdomain(req)
		case <-t.C:
			bfs.SetActive(false)
		case <-bfs.Quit():
			break loop
		}
	}
}

// Returns true if the subdomain name is a duplicate entry in the filter.
// If not, the subdomain name is added to the filter
func (bfs *BruteForceService) duplicate(sub string) bool {
	bfs.Lock()
	defer bfs.Unlock()

	if _, found := bfs.subdomains[sub]; found {
		return true
	}
	bfs.subdomains[sub] = struct{}{}
	return false
}

func (bfs *BruteForceService) startRootDomains() {
	if !bfs.Config().BruteForcing {
		return
	}
	// Look at each domain provided by the config
	for _, domain := range bfs.Config().Domains {
		// Check if we have seen the Domain already
		if !bfs.duplicate(domain) {
			go bfs.performBruteForcing(domain, domain)
		}
	}
}

func (bfs *BruteForceService) checkForNewSubdomain(req *AmassRequest) {
	if !bfs.Config().BruteForcing {
		return
	}
	// If the Name is empty or recursive brute forcing is off, we are done here
	if req.Name == "" || !bfs.Config().Recursive {
		return
	}

	labels := strings.Split(req.Name, ".")
	num := len(labels)
	// Is this large enough to consider further?
	if num < 3 {
		return
	}
	// Have we already seen this subdomain?
	sub := strings.Join(labels[1:], ".")
	if bfs.duplicate(sub) {
		return
	}
	// It needs to have more labels than the root domain
	if num-1 <= len(strings.Split(req.Domain, ".")) {
		return
	}
	// Otherwise, run the brute forcing on the proper subdomain
	go bfs.performBruteForcing(sub, req.Domain)
}

func (bfs *BruteForceService) performBruteForcing(subdomain, root string) {
	for _, word := range bfs.Config().Wordlist {
		bfs.SetActive(true)

		bfs.SendOut(&AmassRequest{
			Name:   word + "." + subdomain,
			Domain: root,
			Tag:    BRUTE,
			Source: "Brute Forcing",
		})
		// Going too fast will overwhelm the dns
		// service and overuse memory
		time.Sleep(bfs.Config().Frequency * 2)
	}
}
