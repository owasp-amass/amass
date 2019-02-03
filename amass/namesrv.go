// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/handlers"
	"github.com/OWASP/Amass/amass/utils"
)

type timesRequest struct {
	Subdomain string
	Times     chan int
}

// NameService is the Service that handles all newly discovered names
// within the architecture. This is achieved by receiving all the RESOLVED events.
type NameService struct {
	core.BaseService

	filter            *utils.StringFilter
	times             *utils.Queue
	sanityRE          *regexp.Regexp
	trustedNameFilter *utils.StringFilter
	otherNameFilter   *utils.StringFilter
	graph             handlers.DataHandler
}

// NewNameService requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewNameService(config *core.Config, bus *core.EventBus) *NameService {
	ns := &NameService{
		filter:            utils.NewStringFilter(),
		times:             utils.NewQueue(),
		sanityRE:          utils.AnySubdomainRegex(),
		trustedNameFilter: utils.NewStringFilter(),
		otherNameFilter:   utils.NewStringFilter(),
	}
	ns.BaseService = *core.NewBaseService(ns, "Name Service", config, bus)
	return ns
}

// OnStart implements the Service interface
func (ns *NameService) OnStart() error {
	ns.BaseService.OnStart()

	ns.Bus().Subscribe(core.NewNameTopic, ns.newNameEvent)
	ns.Bus().Subscribe(core.NameResolvedTopic, ns.Resolved)
	go ns.processTimesRequests()
	go ns.processRequests()
	return nil
}

// RegisterGraph makes the Graph available to the NameService.
func (ns *NameService) RegisterGraph(graph handlers.DataHandler) {
	ns.graph = graph
}

func (ns *NameService) newNameEvent(req *core.Request) {
	if req == nil || req.Name == "" || req.Domain == "" {
		return
	}

	req.Name = strings.ToLower(utils.RemoveAsteriskLabel(req.Name))
	req.Domain = strings.ToLower(req.Domain)

	tt := TrustedTag(req.Tag)
	if !tt && ns.otherNameFilter.Duplicate(req.Name) {
		return
	} else if tt && ns.trustedNameFilter.Duplicate(req.Name) {
		return
	}
	ns.SendRequest(req)
}

func (ns *NameService) processRequests() {
	for {
		select {
		case <-ns.PauseChan():
			<-ns.ResumeChan()
		case <-ns.Quit():
			return
		case req := <-ns.RequestChan():
			ns.performRequest(req)
		}
	}
}

func (ns *NameService) performRequest(req *core.Request) {
	ns.SetActive()
	if ns.Config().Passive {
		if !ns.filter.Duplicate(req.Name) {
			ns.Bus().Publish(core.OutputTopic, &core.Output{
				Name:   req.Name,
				Domain: req.Domain,
				Tag:    req.Tag,
				Source: req.Source,
			})
		}
		return
	}
	ns.Bus().Publish(core.ResolveNameTopic, req)
}

// Resolved is called when a name has been resolved by the DNS Service.
func (ns *NameService) Resolved(req *core.Request) {
	ns.SetActive()

	if ns.Config().IsDomainInScope(req.Name) {
		ns.checkSubdomain(req)
	}
}

func (ns *NameService) checkSubdomain(req *core.Request) {
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

	sub := strings.Join(labels[1:], ".")
	// CNAMEs are not a proper subdomain
	cname := ns.graph.IsCNAMENode(&handlers.DataOptsParams{
		UUID:   ns.Config().UUID.String(),
		Name:   req.Name,
		Domain: req.Domain,
	})
	if cname {
		return
	}

	ns.Bus().Publish(core.NewSubdomainTopic, &core.Request{
		Name:   sub,
		Domain: req.Domain,
		Tag:    req.Tag,
		Source: req.Source,
	}, ns.timesForSubdomain(sub))
}

func (ns *NameService) timesForSubdomain(sub string) int {
	times := make(chan int)

	ns.times.Append(&timesRequest{
		Subdomain: sub,
		Times:     times,
	})
	return <-times
}

func (ns *NameService) processTimesRequests() {
	curIdx := 0
	maxIdx := 9
	delays := []int{10, 25, 50, 75, 100, 150, 250, 500, 750, 1000}
	subdomains := make(map[string]int)

	for {
		select {
		case <-ns.Quit():
			return
		default:
			element, ok := ns.times.Next()
			if !ok {
				if curIdx < maxIdx {
					curIdx++
				}
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				continue
			}

			curIdx = 0
			req := element.(*timesRequest)
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
