// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/dnssrv"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// SubdomainService is the AmassService that handles all newly discovered names
// within the architecture. This is achieved by receiving all the RESOLVED events.
type SubdomainService struct {
	core.BaseAmassService

	bus evbus.Bus

	// Ensures we do not completely process names more than once
	filter *utils.NameFilter

	// Subdomain names that have been seen and how many times
	subdomains map[string]int
}

// NewSubdomainService requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewSubdomainService(config *core.AmassConfig, bus evbus.Bus) *SubdomainService {
	ss := &SubdomainService{
		bus:        bus,
		filter:     utils.NewNameFilter(),
		subdomains: make(map[string]int),
	}

	ss.BaseAmassService = *core.NewBaseAmassService("Subdomain Service", config, ss)
	return ss
}

// OnStart implements the AmassService interface
func (ss *SubdomainService) OnStart() error {
	ss.BaseAmassService.OnStart()

	ss.bus.SubscribeAsync(core.NEWNAME, ss.SendRequest, false)
	ss.bus.SubscribeAsync(core.RESOLVED, ss.performCheck, false)
	go ss.processRequests()
	return nil
}

// OnPause implements the AmassService interface
func (ss *SubdomainService) OnPause() error {
	return nil
}

// OnResume implements the AmassService interface
func (ss *SubdomainService) OnResume() error {
	return nil
}

// OnStop implements the AmassService interface
func (ss *SubdomainService) OnStop() error {
	ss.BaseAmassService.OnStop()

	ss.bus.Unsubscribe(core.NEWNAME, ss.SendRequest)
	ss.bus.Unsubscribe(core.CHECKED, ss.performCheck)
	return nil
}

func (ss *SubdomainService) processRequests() {
	var count int
	var paused bool

	for {
		select {
		case <-ss.PauseChan():
			paused = true
		case <-ss.ResumeChan():
			paused = false
		case <-ss.Quit():
			return
		default:
			if paused {
				time.Sleep(time.Second)
				continue
			}
			if req := ss.NextRequest(); req != nil {
				count = 0
				go ss.performRequest(req)
			} else {
				count++
				if count == 10 {
					time.Sleep(100 * time.Millisecond)
					count = 0
				}
			}
		}
	}
}

func (ss *SubdomainService) performRequest(req *core.AmassRequest) {
	if req == nil || req.Name == "" || req.Domain == "" {
		ss.Config().MaxFlow.Release(1)
		return
	}
	req.Name = strings.ToLower(utils.RemoveAsteriskLabel(req.Name))
	req.Domain = strings.ToLower(req.Domain)
	if ss.Config().Passive {
		if !ss.filter.Duplicate(req.Name) {
			ss.bus.Publish(core.OUTPUT, &core.AmassOutput{
				Name:   req.Name,
				Domain: req.Domain,
				Tag:    req.Tag,
				Source: req.Source,
			})
		}
		ss.Config().MaxFlow.Release(1)
		return
	}
	ss.bus.Publish(core.DNSQUERY, req)
}

func (ss *SubdomainService) performCheck(req *core.AmassRequest) {
	ss.SetActive()

	if ss.Config().IsDomainInScope(req.Name) {
		ss.checkSubdomain(req)
	}
	if !core.TrustedTag(req.Tag) && dnssrv.MatchesWildcard(req) {
		return
	}
	ss.bus.Publish(core.CHECKED, req)
}

func (ss *SubdomainService) timesForSubdomain(sub string) int {
	ss.Lock()
	defer ss.Unlock()

	times, ok := ss.subdomains[sub]
	if ok {
		times++
	} else {
		times = 1
	}
	ss.subdomains[sub] = times
	return times
}

func (ss *SubdomainService) checkSubdomain(req *core.AmassRequest) {
	labels := strings.Split(req.Name, ".")
	num := len(labels)
	// Is this large enough to consider further?
	if num < 2 {
		return
	}
	// It cannot have fewer labels than the root domain name
	if num-1 < len(strings.Split(req.Domain, ".")) {
		return
	}
	// Do not further evaluate service subdomains
	if labels[1] == "_tcp" || labels[1] == "_udp" || labels[1] == "_tls" {
		return
	}
	// CNAMEs are not a proper subdomain
	sub := strings.Join(labels[1:], ".")
	if ss.Config().Graph().CNAMENode(sub) != nil {
		return
	}

	ss.bus.Publish(core.NEWSUB, &core.AmassRequest{
		Name:   sub,
		Domain: req.Domain,
		Tag:    req.Tag,
		Source: req.Source,
	}, ss.timesForSubdomain(sub))
}
