// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"strconv"
	"strings"
	"time"

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

	h.Bus().Subscribe(core.IPToASNTopic, h.SendASNRequest)
	go h.processRequests()
	return nil
}

func (h *HackerTarget) processRequests() {
	for {
		select {
		case <-h.Quit():
			return
		case dns := <-h.DNSRequestChan():
			if h.Config().IsDomainInScope(dns.Domain) {
				h.executeDNSQuery(dns.Domain)
			}
		case asn := <-h.ASNRequestChan():
			h.executeASNQuery(asn.Address)
		case <-h.AddrRequestChan():
		case <-h.WhoisRequestChan():
		}
	}
}

func (h *HackerTarget) executeDNSQuery(domain string) {
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

func (h *HackerTarget) getDNSURL(domain string) string {
	format := "http://api.hackertarget.com/hostsearch/?q=%s"

	return fmt.Sprintf(format, domain)
}

func (h *HackerTarget) executeASNQuery(addr string) {
	url := h.getASNURL(addr)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		h.Config().Log.Printf("%s: %s: %v", h.String(), url, err)
		return
	}

	fields := strings.Split(page, ",")
	if len(fields) < 4 {
		h.Config().Log.Printf("%s: %s: Failed to parse the response", h.String(), url)
		return
	}

	asn, err := strconv.Atoi(strings.Trim(fields[1], "\""))
	if err != nil {
		h.Config().Log.Printf("%s: %s: Failed to parse the origin response: %v", h.String(), url, err)
		return
	}

	h.Bus().Publish(core.NewASNTopic, &core.ASNRequest{
		ASN:            asn,
		Prefix:         strings.Trim(fields[2], "\""),
		AllocationDate: time.Now(),
		Description:    strings.Trim(fields[3], "\""),
		Netblocks:      []string{strings.Trim(fields[2], "\"")},
		Tag:            h.SourceType,
		Source:         h.String(),
	})
}

func (h *HackerTarget) getASNURL(addr string) string {
	format := "https://api.hackertarget.com/aslookup/?q=%s"

	return fmt.Sprintf(format, addr)
}
