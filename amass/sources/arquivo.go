// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// Arquivo is the AmassService that handles access to the Arquivo data source.
type Arquivo struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewArquivo requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewArquivo(bus evbus.Bus, config *core.AmassConfig) *Arquivo {
	a := &Arquivo{
		Bus:        bus,
		Config:     config,
		baseURL:    "http://arquivo.pt/wayback",
		SourceType: core.ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	a.BaseAmassService = *core.NewBaseAmassService("Arquivo", a)
	return a
}

// OnStart implements the AmassService interface
func (a *Arquivo) OnStart() error {
	a.BaseAmassService.OnStart()

	a.Bus.SubscribeAsync(core.CHECKED, a.SendRequest, false)
	go a.startRootDomains()
	go a.processRequests()
	return nil
}

// OnStop implements the AmassService interface
func (a *Arquivo) OnStop() error {
	a.BaseAmassService.OnStop()

	a.Bus.Unsubscribe(core.CHECKED, a.SendRequest)
	return nil
}

func (a *Arquivo) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range a.Config.Domains() {
		a.executeQuery(domain, domain)
	}
}

func (a *Arquivo) processRequests() {
	for {
		select {
		case <-a.Quit():
			return
		case req := <-a.RequestChan():
			a.executeQuery(req.Name, req.Domain)
		}
	}
}

func (a *Arquivo) executeQuery(sn, domain string) {
	if sn == "" || domain == "" {
		return
	}
	if a.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(a, a.baseURL, domain, sn)
	if err != nil {
		a.Config.Log.Printf("%s: %v", a.String(), err)
		return
	}

	for _, name := range names {
		n := cleanName(name)

		if core.DataSourceNameFilter.Duplicate(n) {
			continue
		}

		a.Bus.Publish(core.NEWNAME, &core.AmassRequest{
			Name:   n,
			Domain: domain,
			Tag:    a.SourceType,
			Source: a.String(),
		})
	}
}
