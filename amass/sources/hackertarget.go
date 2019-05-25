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

	go h.processRequests()
	return nil
}

func (h *HackerTarget) processRequests() {
	for {
		select {
		case <-h.Quit():
			return
		case req := <-h.RequestChan():
			if h.Config().IsDomainInScope(req.Domain) {
				h.executeQuery(req.Domain)
			}
		}
	}
}

func (h *HackerTarget) executeQuery(domain string) {
	re := h.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	h.SetActive()
	url := h.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		h.Config().Log.Printf("%s: %s: %v", h.String(), url, err)
		return
	}

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
