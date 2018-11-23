// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"

	"github.com/OWASP/Amass/amass/utils"
)

// HackerTarget is the AmassService that handles access to the HackerTarget data source.
type HackerTarget struct {
	BaseAmassService

	SourceType string
}

// NewHackerTarget returns he object initialized, but not yet started.
func NewHackerTarget(e *Enumeration) *HackerTarget {
	h := &HackerTarget{SourceType: API}

	h.BaseAmassService = *NewBaseAmassService(e, "HackerTarget", h)
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
	for _, domain := range h.Enum().Config.Domains() {
		h.executeQuery(domain)
	}
}

func (h *HackerTarget) executeQuery(domain string) {
	url := h.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		h.Enum().Log.Printf("%s: %s: %v", h.String(), url, err)
		return
	}

	h.SetActive()
	re := h.Enum().Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		h.Enum().NewNameEvent(&AmassRequest{
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
