// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

type timesRequest struct {
	Subdomain string
	Times     chan int
}

// NameService is the AmassService that handles all newly discovered names
// within the architecture. This is achieved by receiving all the RESOLVED events.
type NameService struct {
	core.BaseAmassService

	Bus         evbus.Bus
	Config      *core.AmassConfig
	filter      *utils.StringFilter
	timesChan   chan *timesRequest
	releases    chan struct{}
	completions chan time.Time
}

// NewNameService requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewNameService(bus evbus.Bus, config *core.AmassConfig) *NameService {
	max := core.TimingToMaxFlow(config.Timing) + core.TimingToReleasesPerSecond(config.Timing)
	ns := &NameService{
		Bus:         bus,
		Config:      config,
		filter:      utils.NewStringFilter(),
		timesChan:   make(chan *timesRequest, max),
		releases:    make(chan struct{}, max),
		completions: make(chan time.Time, max),
	}

	ns.BaseAmassService = *core.NewBaseAmassService("Name Service", ns)
	return ns
}

// OnStart implements the AmassService interface
func (ns *NameService) OnStart() error {
	ns.BaseAmassService.OnStart()

	ns.Bus.SubscribeAsync(core.NEWNAME, ns.SendRequest, false)
	ns.Bus.SubscribeAsync(core.RESOLVED, ns.performCheck, false)
	ns.Bus.SubscribeAsync(core.RELEASEREQ, ns.sendRelease, false)
	go ns.processTimesRequests()
	go ns.processRequests()
	go ns.processReleases()
	return nil
}

// OnStop implements the AmassService interface
func (ns *NameService) OnStop() error {
	ns.BaseAmassService.OnStop()

	ns.Bus.Unsubscribe(core.NEWNAME, ns.SendRequest)
	ns.Bus.Unsubscribe(core.RESOLVED, ns.performCheck)
	ns.Bus.Unsubscribe(core.RELEASEREQ, ns.sendRelease)
	return nil
}

func (ns *NameService) processRequests() {
	var perSec []int
	var completionTimes []time.Time

	t := time.NewTicker(time.Second)
	defer t.Stop()
	logTick := time.NewTicker(time.Minute)
	defer logTick.Stop()
	for {
		select {
		case <-ns.PauseChan():
			<-ns.ResumeChan()
		case <-ns.Quit():
			return
		case comp := <-ns.completions:
			completionTimes = append(completionTimes, comp)
		case <-t.C:
			perSec = append(perSec, len(completionTimes))
			completionTimes = []time.Time{}
		case <-logTick.C:
			num := len(perSec)
			var total int
			for _, s := range perSec {
				total += s
			}
			ns.Config.Log.Printf("Average requests processed: %d/sec", total/num)
			perSec = []int{}
		case req := <-ns.RequestChan():
			go ns.performRequest(req)
		}
	}
}

func (ns *NameService) sendCompletionTime(t time.Time) {
	ns.completions <- t
}

func (ns *NameService) performRequest(req *core.AmassRequest) {
	if req == nil || req.Name == "" || req.Domain == "" || ns.filter.Duplicate(req.Name) {
		// This is a bad request, and the resource needs to be released immediately
		ns.Config.MaxFlow.Release(1)
		return
	}

	ns.SetActive()
	go ns.sendCompletionTime(time.Now())
	req.Name = strings.ToLower(utils.RemoveAsteriskLabel(req.Name))
	req.Domain = strings.ToLower(req.Domain)
	if ns.Config.Passive {
		ns.Bus.Publish(core.OUTPUT, &core.AmassOutput{
			Name:   req.Name,
			Domain: req.Domain,
			Tag:    req.Tag,
			Source: req.Source,
		})
		ns.sendRelease()
		return
	}
	ns.Bus.Publish(core.DNSQUERY, req)
}

func (ns *NameService) performCheck(req *core.AmassRequest) {
	ns.SetActive()

	if ns.Config.IsDomainInScope(req.Name) {
		ns.checkSubdomain(req)
	}
	if req.Tag == core.DNS {
		ns.sendCompletionTime(time.Now())
	}
	ns.Bus.Publish(core.CHECKED, req)
}

func (ns *NameService) checkSubdomain(req *core.AmassRequest) {
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
	if ns.Config.Graph().CNAMENode(sub) != nil {
		return
	}

	ns.Bus.Publish(core.NEWSUB, &core.AmassRequest{
		Name:   sub,
		Domain: req.Domain,
		Tag:    req.Tag,
		Source: req.Source,
	}, ns.timesForSubdomain(sub))
}

func (ns *NameService) timesForSubdomain(sub string) int {
	times := make(chan int)

	ns.timesChan <- &timesRequest{
		Subdomain: sub,
		Times:     times,
	}
	return <-times
}

func (ns *NameService) processTimesRequests() {
	subdomains := make(map[string]int)

	for {
		select {
		case <-ns.Quit():
			return
		case req := <-ns.timesChan:
			times, ok := subdomains[req.Subdomain]
			if ok {
				times++
			} else {
				times = 1
			}
			subdomains[req.Subdomain] = times
			req.Times <- times
		}
	}
}

func (ns *NameService) sendRelease() {
	ns.releases <- struct{}{}
}

func (ns *NameService) processReleases() {
	t := time.NewTicker(core.TimingToReleaseDelay(ns.Config.Timing))
	defer t.Stop()

	var rcount int
	for {
		select {
		case <-ns.Quit():
			return
		case <-t.C:
			if rcount > 0 {
				ns.Config.MaxFlow.Release(1)
				rcount--
			}
		case <-ns.releases:
			rcount++
		}
	}
}
