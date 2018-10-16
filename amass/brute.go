// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/dnssrv"
	evbus "github.com/asaskevich/EventBus"
)

type BruteForceService struct {
	core.BaseAmassService

	bus evbus.Bus
}

func NewBruteForceService(config *core.AmassConfig, bus evbus.Bus) *BruteForceService {
	bfs := &BruteForceService{bus: bus}

	bfs.BaseAmassService = *core.NewBaseAmassService("Brute Forcing Service", config, bfs)
	return bfs
}

func (bfs *BruteForceService) OnStart() error {
	bfs.BaseAmassService.OnStart()

	if bfs.Config().BruteForcing {
		go bfs.startRootDomains()

		if bfs.Config().Recursive {
			bfs.bus.SubscribeAsync(core.NEWSUB, bfs.NewSubdomain, false)
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
		bfs.bus.Unsubscribe(core.NEWSUB, bfs.NewSubdomain)
	}
	return nil
}

func (bfs *BruteForceService) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range bfs.Config().Domains() {
		go bfs.performBruteForcing(domain, domain)
	}
}

func (bfs *BruteForceService) NewSubdomain(req *core.AmassRequest, times int) {
	if times == bfs.Config().MinForRecursive {
		// Does this subdomain have a wildcard?
		if dnssrv.HasWildcard(req.Domain, req.Name) {
			return
		}

		bfs.performBruteForcing(req.Name, req.Domain)
	}
}

func (bfs *BruteForceService) performBruteForcing(subdomain, root string) {
	for _, word := range bfs.Config().Wordlist {
		bfs.SetActive()

		bfs.bus.Publish(core.NEWNAME, &core.AmassRequest{
			Name:   word + "." + subdomain,
			Domain: root,
			Tag:    core.BRUTE,
			Source: "Brute Force",
		})
	}
}
