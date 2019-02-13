// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// BufferOver is the Service that handles access to the BufferOver data source.
type BufferOver struct {
	core.BaseService

	SourceType string
}

// NewBufferOver returns he object initialized, but not yet started.
func NewBufferOver(config *core.Config, bus *core.EventBus) *BufferOver {
	h := &BufferOver{SourceType: core.API}

	h.BaseService = *core.NewBaseService(h, "BufferOver", config, bus)
	return h
}

// OnStart implements the Service interface
func (h *BufferOver) OnStart() error {
	h.BaseService.OnStart()

	go h.startRootDomains()
	return nil
}

func (h *BufferOver) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range h.Config().Domains() {
		h.executeQuery(domain)
	}
}

func (h *BufferOver) executeQuery(domain string) {
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

func (h *BufferOver) getURL(domain string) string {
	format := "dns.bufferover.run?q=%s"

	return fmt.Sprintf(format, domain)
}
