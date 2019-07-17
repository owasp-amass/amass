// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	eb "github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
)

// HackerOne is the Service that handles access to the unofficial
// HackerOne disclosure timeline data source.
type HackerOne struct {
	core.BaseService

	SourceType string
}

// NewHackerOne returns he object initialized, but not yet started.
func NewHackerOne(config *core.Config, bus *eb.EventBus) *HackerOne {
	h := &HackerOne{SourceType: core.API}

	h.BaseService = *core.NewBaseService(h, "HackerOne", config, bus)
	return h
}

// OnStart implements the Service interface
func (h *HackerOne) OnStart() error {
	h.BaseService.OnStart()

	go h.processRequests()
	return nil
}

func (h *HackerOne) processRequests() {
	for {
		select {
		case <-h.Quit():
			return
		case dns := <-h.DNSRequestChan():
			if h.Config().IsDomainInScope(dns.Domain) {
				h.executeDNSQuery(dns.Domain)
			}
		case <-h.ASNRequestChan():
		case <-h.AddrRequestChan():
		case <-h.WhoisRequestChan():
		}
	}
}

func (h *HackerOne) executeDNSQuery(domain string) {
	re := h.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	h.SetActive()
	url := h.getDNSURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		h.Config().Log.Printf("%s: %s: %v", h.String(), url, err)
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		h.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    h.SourceType,
			Source: h.String(),
		})
	}
}

func (h *HackerOne) getDNSURL(domain string) string {
	format := "http://h1.nobbd.de/search.php?q=%s"

	return fmt.Sprintf(format, domain)
}
