// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	evbus "github.com/asaskevich/EventBus"
)

type BruteForceService struct {
	core.BaseAmassService

	bus evbus.Bus

	// Subdomains that have been worked on by brute forcing
	subdomains map[string]int
}

func NewBruteForceService(config *core.AmassConfig, bus evbus.Bus) *BruteForceService {
	bfs := &BruteForceService{
		bus:        bus,
		subdomains: make(map[string]int),
	}

	bfs.BaseAmassService = *core.NewBaseAmassService("Brute Forcing Service", config, bfs)
	return bfs
}

func (bfs *BruteForceService) OnStart() error {
	bfs.BaseAmassService.OnStart()

	if bfs.Config().BruteForcing {
		go bfs.startRootDomains()

		if bfs.Config().Recursive {
			bfs.bus.SubscribeAsync(core.RESOLVED, bfs.SendRequest, false)
			go bfs.processRequests()
		}
	}
	return nil
}

func (bfs *BruteForceService) OnPause() error {
	return nil
}

func (bfs *BruteForceService) OnResume() error {
	return nil
}

func (bfs *BruteForceService) OnStop() error {
	bfs.BaseAmassService.OnStop()

	if bfs.Config().BruteForcing && bfs.Config().Recursive {
		bfs.bus.Unsubscribe(core.RESOLVED, bfs.SendRequest)
	}
	return nil
}

func (bfs *BruteForceService) processRequests() {
	t := time.NewTicker(10 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			if req := bfs.NextRequest(); req != nil {
				bfs.checkForNewSubdomain(req)
			}
		case <-bfs.PauseChan():
			t.Stop()
		case <-bfs.ResumeChan():
			t = time.NewTicker(10 * time.Millisecond)
		case <-bfs.Quit():
			return
		}
	}
}

// Returns true if the subdomain name is a duplicate entry in the filter.
// If not, the subdomain name is added to the filter
func (bfs *BruteForceService) subDiscoveries(sub string) int {
	bfs.Lock()
	defer bfs.Unlock()

	if dis, found := bfs.subdomains[sub]; found {
		dis += 1
		bfs.subdomains[sub] = dis
		return dis
	}
	bfs.subdomains[sub] = 1
	return 1
}

func (bfs *BruteForceService) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range bfs.Config().Domains() {
		go bfs.performBruteForcing(domain, domain)
	}
}

func (bfs *BruteForceService) checkForNewSubdomain(req *core.AmassRequest) {
	if req.Name == "" || req.Domain == "" || !bfs.Config().IsDomainInScope(req.Name) {
		return
	}

	labels := strings.Split(req.Name, ".")
	num := len(labels)
	// It needs to have more labels than the root domain
	if num-1 <= len(strings.Split(req.Domain, ".")) {
		return
	}
	// Check the subdomain of the request name
	if labels[1] == "_tcp" || labels[1] == "_udp" {
		return
	}
	sub := strings.Join(labels[1:], ".")
	if bfs.subDiscoveries(sub) == bfs.Config().MinForRecursive {
		go bfs.performBruteForcing(sub, req.Domain)
	}
}

func (bfs *BruteForceService) performBruteForcing(subdomain, root string) {
	for _, word := range bfs.Config().Wordlist {
		bfs.SetActive()

		bfs.bus.Publish(core.DNSQUERY, &core.AmassRequest{
			Name:   word + "." + subdomain,
			Domain: root,
			Tag:    core.BRUTE,
			Source: "Brute Force",
		})
	}
}
