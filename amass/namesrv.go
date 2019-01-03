// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

type timesRequest struct {
	Subdomain string
	Times     chan int
}

// NameService is the Service that handles all newly discovered names
// within the architecture. This is achieved by receiving all the RESOLVED events.
type NameService struct {
	BaseService

	filter      *utils.StringFilter
	timesChan   chan *timesRequest
	releases    chan struct{}
	completions chan time.Time
	sanityRE    *regexp.Regexp
}

// NewNameService requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewNameService(e *Enumeration) *NameService {
	max := e.Config.Timing.ToMaxFlow() + e.Config.Timing.ToReleasesPerSecond()
	ns := &NameService{
		filter:      utils.NewStringFilter(),
		timesChan:   make(chan *timesRequest, max),
		releases:    make(chan struct{}, max),
		completions: make(chan time.Time, max),
		sanityRE:    utils.AnySubdomainRegex(),
	}

	ns.BaseService = *NewBaseService(e, "Name Service", ns)
	return ns
}

// OnStart implements the Service interface
func (ns *NameService) OnStart() error {
	ns.BaseService.OnStart()

	go ns.processTimesRequests()
	go ns.processRequests()
	return nil
}

func (ns *NameService) processRequests() {
	var perSec []int
	var completionTimes []time.Time
	last := time.Now()
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
			var num int
			for _, com := range completionTimes {
				if com.After(last) {
					num++
				}
			}
			perSec = append(perSec, num)
			completionTimes = []time.Time{}
			last = time.Now()
		case <-logTick.C:
			num := len(perSec)
			var total int
			for _, s := range perSec {
				total += s
			}
			if num > 0 {
				ns.Enum().Log.Printf("Average DNS names processed: %d/sec", total/num)
			}
			perSec = []int{}
		case req := <-ns.RequestChan():
			go ns.performRequest(req)
		}
	}
}

func (ns *NameService) sendCompletionTime(t time.Time) {
	ns.completions <- t
}

func (ns *NameService) performRequest(req *Request) {
	ns.SetActive()
	ns.sendCompletionTime(time.Now())
	if ns.Enum().Config.Passive {
		if !ns.filter.Duplicate(req.Name) {
			ns.Enum().OutputEvent(&Output{
				Name:   req.Name,
				Domain: req.Domain,
				Tag:    req.Tag,
				Source: req.Source,
			})
		}
		return
	}
	ns.Enum().ResolveNameEvent(req)
}

// Resolved is called when a name has been resolved by the DNS Service.
func (ns *NameService) Resolved(req *Request) {
	ns.SetActive()

	if ns.Enum().Config.IsDomainInScope(req.Name) {
		go ns.checkSubdomain(req)
	}
	if req.Tag == DNS {
		ns.sendCompletionTime(time.Now())
	}
	ns.Enum().CheckedNameEvent(req)
	ns.SetActive()
}

func (ns *NameService) checkSubdomain(req *Request) {
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
	ns.Enum().NewSubdomainEvent(&Request{
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
