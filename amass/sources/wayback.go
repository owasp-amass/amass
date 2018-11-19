// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// Wayback is the AmassService that handles access to the Wayback data source.
type Wayback struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewWayback requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewWayback(bus evbus.Bus, config *core.AmassConfig) *Wayback {
	w := &Wayback{
		Bus:        bus,
		Config:     config,
		baseURL:    "http://web.archive.org/web",
		SourceType: core.ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	w.BaseAmassService = *core.NewBaseAmassService("Wayback", w)
	return w
}

// OnStart implements the AmassService interface
func (w *Wayback) OnStart() error {
	w.BaseAmassService.OnStart()

	w.Bus.SubscribeAsync(core.CHECKED, w.SendRequest, false)
	go w.startRootDomains()
	go w.processRequests()
	return nil
}

// OnStop implements the AmassService interface
func (w *Wayback) OnStop() error {
	w.BaseAmassService.OnStop()

	w.Bus.Unsubscribe(core.CHECKED, w.SendRequest)
	return nil
}

func (w *Wayback) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range w.Config.Domains() {
		w.executeQuery(domain, domain)
	}
}

func (w *Wayback) processRequests() {
	for {
		select {
		case <-w.Quit():
			return
		case req := <-w.RequestChan():
			w.executeQuery(req.Name, req.Domain)
		}
	}
}

func (w *Wayback) executeQuery(sn, domain string) {
	if sn == "" || domain == "" {
		return
	}
	if w.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(w, w.baseURL, domain, sn)
	if err != nil {
		w.Config.Log.Printf("%s: %v", w.String(), err)
		return
	}

	for _, n := range names {
		go func(name string) {
			w.Config.MaxFlow.Acquire(1)
			w.Bus.Publish(core.NEWNAME, &core.AmassRequest{
				Name:   cleanName(name),
				Domain: domain,
				Tag:    w.SourceType,
				Source: w.String(),
			})
		}(n)
	}
}
