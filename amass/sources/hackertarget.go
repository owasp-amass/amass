// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// HackerTarget is the AmassService that handles access to the HackerTarget data source.
type HackerTarget struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	SourceType string
	filter     *utils.StringFilter
}

// NewHackerTarget requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewHackerTarget(bus evbus.Bus, config *core.AmassConfig) *HackerTarget {
	h := &HackerTarget{
		Bus:        bus,
		Config:     config,
		SourceType: core.API,
		filter:     utils.NewStringFilter(),
	}

	h.BaseAmassService = *core.NewBaseAmassService("HackerTarget", h)
	return h
}

// OnStart implements the AmassService interface
func (h *HackerTarget) OnStart() error {
	h.BaseAmassService.OnStart()

	go h.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (h *HackerTarget) OnStop() error {
	h.BaseAmassService.OnStop()
	return nil
}

func (h *HackerTarget) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range h.Config.Domains() {
		h.executeQuery(domain)
	}
}

func (h *HackerTarget) executeQuery(domain string) {
	url := h.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		h.Config.Log.Printf("%s: %s: %v", h.String(), url, err)
		return
	}

	h.SetActive()
	re := h.Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		n := cleanName(sd)

		if h.filter.Duplicate(n) {
			continue
		}
		go func(name string) {
			h.Config.MaxFlow.Acquire(1)
			h.Bus.Publish(core.NEWNAME, &core.AmassRequest{
				Name:   name,
				Domain: domain,
				Tag:    h.SourceType,
				Source: h.String(),
			})
		}(n)
	}
}

func (h *HackerTarget) getURL(domain string) string {
	format := "http://api.hackertarget.com/hostsearch/?q=%s"

	return fmt.Sprintf(format, domain)
}
