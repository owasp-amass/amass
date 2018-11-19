// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// LoCArchive is the AmassService that handles access to the LoCArchive data source.
type LoCArchive struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewLoCArchive requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewLoCArchive(bus evbus.Bus, config *core.AmassConfig) *LoCArchive {
	l := &LoCArchive{
		Bus:        bus,
		Config:     config,
		baseURL:    "http://webarchive.loc.gov/all",
		SourceType: core.ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	l.BaseAmassService = *core.NewBaseAmassService("LoCArchive", l)
	return l
}

// OnStart implements the AmassService interface
func (l *LoCArchive) OnStart() error {
	l.BaseAmassService.OnStart()

	l.Bus.SubscribeAsync(core.CHECKED, l.SendRequest, false)
	go l.startRootDomains()
	go l.processRequests()
	return nil
}

// OnStop implements the AmassService interface
func (l *LoCArchive) OnStop() error {
	l.BaseAmassService.OnStop()

	l.Bus.Unsubscribe(core.CHECKED, l.SendRequest)
	return nil
}

func (l *LoCArchive) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range l.Config.Domains() {
		l.executeQuery(domain, domain)
	}
}

func (l *LoCArchive) processRequests() {
	for {
		select {
		case <-l.Quit():
			return
		case req := <-l.RequestChan():
			l.executeQuery(req.Name, req.Domain)
		}
	}
}

func (l *LoCArchive) executeQuery(sn, domain string) {
	if sn == "" || domain == "" {
		return
	}
	if l.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(l, l.baseURL, domain, sn)
	if err != nil {
		l.Config.Log.Printf("%s: %v", l.String(), err)
		return
	}

	for _, n := range names {
		go func(name string) {
			l.Config.MaxFlow.Acquire(1)
			l.Bus.Publish(core.NEWNAME, &core.AmassRequest{
				Name:   name,
				Domain: domain,
				Tag:    l.SourceType,
				Source: l.String(),
			})
		}(n)
	}
}
