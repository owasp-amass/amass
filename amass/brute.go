// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strings"
	"time"
)

// BruteForceService is the AmassService that handles all brute force name generation
// within the architecture. This is achieved by watching all the NEWSUB events.
type BruteForceService struct {
	BaseAmassService
}

// NewBruteForceService returns he object initialized, but not yet started.
func NewBruteForceService(e *Enumeration) *BruteForceService {
	bfs := new(BruteForceService)

	bfs.BaseAmassService = *NewBaseAmassService(e, "Brute Forcing", bfs)
	return bfs
}

// OnStart implements the AmassService interface
func (bfs *BruteForceService) OnStart() error {
	bfs.BaseAmassService.OnStart()

	if bfs.Enum().Config.BruteForcing {
		go bfs.startRootDomains()

		if bfs.Enum().Config.Recursive {
			bfs.Enum().Bus.SubscribeAsync(NEWSUB, bfs.newSubdomain, false)
		}
	}
	return nil
}

// OnStop implements the AmassService interface
func (bfs *BruteForceService) OnStop() error {
	bfs.BaseAmassService.OnStop()

	if bfs.Enum().Config.BruteForcing && bfs.Enum().Config.Recursive {
		bfs.Enum().Bus.Unsubscribe(NEWSUB, bfs.newSubdomain)
	}
	return nil
}

func (bfs *BruteForceService) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range bfs.Enum().Config.Domains() {
		bfs.performBruteForcing(domain, domain)
	}
}

func (bfs *BruteForceService) newSubdomain(req *AmassRequest, times int) {
	if times == bfs.Enum().Config.MinForRecursive {
		bfs.performBruteForcing(req.Name, req.Domain)
	}
}

func (bfs *BruteForceService) performBruteForcing(subdomain, root string) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for _, word := range bfs.Enum().Config.Wordlist {
		select {
		case <-t.C:
			bfs.SetActive()
		case <-bfs.Quit():
			return
		default:
			req := &AmassRequest{
				Name:   strings.ToLower(word + "." + subdomain),
				Domain: root,
				Tag:    BRUTE,
				Source: bfs.String(),
			}

			if bfs.Enum().DupDataSourceName(req) {
				continue
			}
			bfs.Enum().Bus.Publish(NEWNAME, req)
		}
	}
}
