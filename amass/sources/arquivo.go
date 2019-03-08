// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// Arquivo is the Service that handles access to the Arquivo data source.
type Arquivo struct {
	core.BaseService

	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewArquivo returns he object initialized, but not yet started.
func NewArquivo(config *core.Config, bus *core.EventBus) *Arquivo {
	a := &Arquivo{
		baseURL:    "http://arquivo.pt/wayback",
		SourceType: core.ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	a.BaseService = *core.NewBaseService(a, "Arquivo", config, bus)
	return a
}

// OnStart implements the Service interface
func (a *Arquivo) OnStart() error {
	a.BaseService.OnStart()

	a.Bus().Subscribe(core.NameResolvedTopic, a.SendRequest)
	go a.processRequests()
	return nil
}

func (a *Arquivo) processRequests() {
	for {
		select {
		case <-a.Quit():
			return
		case req := <-a.RequestChan():
			if a.Config().IsDomainInScope(req.Name) {
				a.executeQuery(req.Name, req.Domain)
			}
		}
	}
}

func (a *Arquivo) executeQuery(sn, domain string) {
	if sn == "" || domain == "" || a.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(a, a.baseURL, domain, sn)
	if err != nil {
		a.Config().Log.Printf("%s: %v", a.String(), err)
		return
	}

	for _, name := range names {
		a.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    a.SourceType,
			Source: a.String(),
		})
	}
}
