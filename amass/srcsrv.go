// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"regexp"
	"strings"
	"time"

	evbus "github.com/asaskevich/EventBus"
	"github.com/caffix/amass/amass/sources"
)

type entry struct {
	Source sources.DataSource
	Domain string
	Sub    string
}

type SourcesService struct {
	BaseAmassService

	bus           evbus.Bus
	responses     chan *AmassRequest
	directs       []sources.DataSource
	throttles     []sources.DataSource
	throttleQueue []*entry
	inFilter      map[string]struct{}
	outFilter     map[string]struct{}
	domainFilter  map[string]struct{}
}

func NewSourcesService(config *AmassConfig, bus evbus.Bus) *SourcesService {
	ss := &SourcesService{
		bus:          bus,
		responses:    make(chan *AmassRequest, 50),
		inFilter:     make(map[string]struct{}),
		outFilter:    make(map[string]struct{}),
		domainFilter: make(map[string]struct{}),
	}

	for _, source := range sources.GetAllSources() {
		if source.Type() == ARCHIVE {
			ss.throttles = append(ss.throttles, source)
		} else {
			ss.directs = append(ss.directs, source)
		}
		source.SetLogger(config.Log)
	}

	ss.BaseAmassService = *NewBaseAmassService("Sources Service", config, ss)
	return ss
}

func (ss *SourcesService) OnStart() error {
	ss.BaseAmassService.OnStart()

	ss.bus.SubscribeAsync(RESOLVED, ss.SendRequest, false)
	go ss.processRequests()
	go ss.processOutput()
	go ss.processThrottleQueue()
	go ss.queryAllSources()
	return nil
}

func (ss *SourcesService) OnStop() error {
	ss.BaseAmassService.OnStop()

	ss.bus.Unsubscribe(RESOLVED, ss.SendRequest)
	return nil
}

func (ss *SourcesService) processRequests() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			if req := ss.NextRequest(); req != nil {
				go ss.handleRequest(req)
			}
		case <-ss.Quit():
			return
		}
	}
}

func (ss *SourcesService) handleRequest(req *AmassRequest) {
	if ss.inDup(req.Name) || !ss.Config().IsDomainInScope(req.Name) {
		return
	}

	ss.SetActive()

	var subsrch bool
	if req.Name != req.Domain {
		subsrch = true
	}

	for _, source := range ss.directs {
		if subsrch && !source.Subdomains() {
			continue
		}
		go ss.queryOneSource(source, req.Domain, req.Name)
	}

	// Do not queue requests that were not resolved
	if len(req.Records) == 0 {
		return
	}

	for _, source := range ss.throttles {
		if subsrch && !source.Subdomains() {
			continue
		}
		ss.throttleAdd(source, req.Domain, req.Name)
	}
}

func (ss *SourcesService) processOutput() {
	for {
		select {
		case req := <-ss.responses:
			ss.handleOutput(req)
		case <-ss.Quit():
			return
		}
	}
}

func (ss *SourcesService) handleOutput(req *AmassRequest) {
	re := regexp.MustCompile("^((20)|(25)|(2f)|(3d)|(40))+")

	// Clean up the names scraped from the web
	if i := re.FindStringIndex(req.Name); i != nil {
		req.Name = req.Name[i[1]:]
	}
	req.Name = strings.TrimSpace(strings.ToLower(req.Name))

	if ss.outDup(req.Name) {
		return
	}

	ss.SetActive()
	if ss.Config().NoDNS {
		ss.bus.Publish(OUTPUT, &AmassOutput{
			Name:   req.Name,
			Domain: req.Domain,
			Tag:    req.Tag,
			Source: req.Source,
		})
	} else {
		ss.bus.Publish(DNSQUERY, req)
	}
	ss.SendRequest(req)
}

func (ss *SourcesService) inDup(sub string) bool {
	ss.Lock()
	defer ss.Unlock()

	if _, found := ss.inFilter[sub]; found {
		return true
	}
	ss.inFilter[sub] = struct{}{}
	return false
}

func (ss *SourcesService) outDup(sub string) bool {
	ss.Lock()
	defer ss.Unlock()

	if _, found := ss.outFilter[sub]; found {
		return true
	}
	ss.outFilter[sub] = struct{}{}
	return false
}

func (ss *SourcesService) queryAllSources() {
	ss.SetActive()

	for _, domain := range ss.Config().Domains() {
		if _, found := ss.domainFilter[domain]; found {
			continue
		}

		ss.SendRequest(&AmassRequest{
			Name:   domain,
			Domain: domain,
		})
	}
}

func (ss *SourcesService) queryOneSource(source sources.DataSource, domain, sub string) {
	for _, name := range source.Query(domain, sub) {
		ss.responses <- &AmassRequest{
			Name:   name,
			Domain: domain,
			Tag:    source.Type(),
			Source: source.String(),
		}
	}
}

func (ss *SourcesService) throttleAdd(source sources.DataSource, domain, sub string) {
	ss.Lock()
	defer ss.Unlock()

	ss.throttleQueue = append(ss.throttleQueue, &entry{
		Source: source,
		Domain: domain,
		Sub:    sub,
	})
}

func (ss *SourcesService) throttleNext() *entry {
	ss.Lock()
	defer ss.Unlock()

	if len(ss.throttleQueue) == 0 {
		return nil
	}

	e := ss.throttleQueue[0]
	if len(ss.throttleQueue) == 1 {
		ss.throttleQueue = []*entry{}
		return e
	}
	ss.throttleQueue = ss.throttleQueue[1:]
	return e
}

const MAX_THROTTLED int = 20

func (ss *SourcesService) processThrottleQueue() {
	var running int
	done := make(chan struct{}, MAX_THROTTLED)

	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			if running >= MAX_THROTTLED {
				continue
			}

			if th := ss.throttleNext(); th != nil {
				running++
				go func() {
					ss.queryOneSource(th.Source, th.Domain, th.Sub)
					done <- struct{}{}
				}()
			}
		case <-done:
			running--
		case <-ss.Quit():
			return
		}
	}
}
