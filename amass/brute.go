// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"time"

	"github.com/OWASP/Amass/amass/core"
	evbus "github.com/asaskevich/EventBus"
)

// BruteForceService is the AmassService that handles all brute force name generation
// within the architecture. This is achieved by watching all the NEWSUB events.
type BruteForceService struct {
	core.BaseAmassService

	Bus    evbus.Bus
	Config *core.AmassConfig
}

// NewBruteForceService requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewBruteForceService(bus evbus.Bus, config *core.AmassConfig) *BruteForceService {
	bfs := &BruteForceService{
		Bus:    bus,
		Config: config,
	}

	bfs.BaseAmassService = *core.NewBaseAmassService("Brute Forcing", bfs)
	return bfs
}

// OnStart implements the AmassService interface
func (bfs *BruteForceService) OnStart() error {
	bfs.BaseAmassService.OnStart()

	if bfs.Config.BruteForcing {
		go bfs.startRootDomains()

		if bfs.Config.Recursive {
			bfs.Bus.SubscribeAsync(core.NEWSUB, bfs.newSubdomain, false)
		}
	}
	return nil
}

// OnStop implements the AmassService interface
func (bfs *BruteForceService) OnStop() error {
	bfs.BaseAmassService.OnStop()

	if bfs.Config.BruteForcing && bfs.Config.Recursive {
		bfs.Bus.Unsubscribe(core.NEWSUB, bfs.newSubdomain)
	}
	return nil
}

func (bfs *BruteForceService) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range bfs.Config.Domains() {
		bfs.performBruteForcing(domain, domain)
	}
}

func (bfs *BruteForceService) newSubdomain(req *core.AmassRequest, times int) {
	if times == bfs.Config.MinForRecursive {
		go bfs.performBruteForcing(req.Name, req.Domain)
	}
}

func (bfs *BruteForceService) performBruteForcing(subdomain, root string) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for _, word := range bfs.Config.Wordlist {
		select {
		case <-t.C:
			bfs.SetActive()
		case <-bfs.Quit():
			return
		default:
			bfs.Config.MaxFlow.Acquire(1)
			bfs.Bus.Publish(core.NEWNAME, &core.AmassRequest{
				Name:   word + "." + subdomain,
				Domain: root,
				Tag:    core.BRUTE,
				Source: bfs.String(),
			})
		}
	}
}
