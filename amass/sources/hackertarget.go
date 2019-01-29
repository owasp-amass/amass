// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// HackerTarget is the Service that handles access to the HackerTarget data source.
type HackerTarget struct {
	core.BaseService

	SourceType string
}

// NewHackerTarget returns he object initialized, but not yet started.
func NewHackerTarget(config *core.Config, bus *core.EventBus) *HackerTarget {
	h := &HackerTarget{SourceType: core.API}

	h.BaseService = *core.NewBaseService(h, "HackerTarget", config, bus)
	return h
}

// OnStart implements the Service interface
func (h *HackerTarget) OnStart() error {
	h.BaseService.OnStart()

	go h.startRootDomains()
	return nil
}

func (h *HackerTarget) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range h.Config().Domains() {
		h.executeQuery(domain)
	}
}

func (h *HackerTarget) executeQuery(domain string) {
	url := h.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		h.Config().Log.Printf("%s: %s: %v", h.String(), url, err)
		return
	}

	h.SetActive()
	re := h.Config().DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		h.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    h.SourceType,
			Source: h.String(),
		})
	}
}

func (h *HackerTarget) getURL(domain string) string {
	format := "http://api.hackertarget.com/hostsearch/?q=%s"

	return fmt.Sprintf(format, domain)
}
