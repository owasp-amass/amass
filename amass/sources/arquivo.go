// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// Arquivo is the AmassService that handles access to the Arquivo data source.
type Arquivo struct {
	core.BaseAmassService

	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewArquivo returns he object initialized, but not yet started.
func NewArquivo(e *core.Enumeration) *Arquivo {
	a := &Arquivo{
		baseURL:    "http://arquivo.pt/wayback",
		SourceType: core.ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	a.BaseAmassService = *core.NewBaseAmassService(e, "Arquivo", a)
	return a
}

// OnStart implements the AmassService interface
func (a *Arquivo) OnStart() error {
	a.BaseAmassService.OnStart()

	a.Enum().Bus.SubscribeAsync(core.CHECKED, a.SendRequest, false)
	go a.startRootDomains()
	go a.processRequests()
	return nil
}

// OnStop implements the AmassService interface
func (a *Arquivo) OnStop() error {
	a.BaseAmassService.OnStop()

	a.Enum().Bus.Unsubscribe(core.CHECKED, a.SendRequest)
	return nil
}

func (a *Arquivo) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range a.Enum().Config.Domains() {
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
		a.Enum().Log.Printf("%s: %v", a.String(), err)
		return
	}

	for _, name := range names {
		req := &core.AmassRequest{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    a.SourceType,
			Source: a.String(),
		}

		if a.Enum().DupDataSourceName(req) {
			continue
		}
		a.Enum().Bus.Publish(core.NEWNAME, req)
	}
}
