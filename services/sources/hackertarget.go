// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

// HackerTarget is the Service that handles access to the HackerTarget data source.
type HackerTarget struct {
	services.BaseService

	SourceType string
}

// NewHackerTarget returns he object initialized, but not yet started.
func NewHackerTarget(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *HackerTarget {
	h := &HackerTarget{SourceType: requests.API}

	h.BaseService = *services.NewBaseService(h, "HackerTarget", cfg, bus, pool)
	return h
}

// OnStart implements the Service interface
func (h *HackerTarget) OnStart() error {
	h.BaseService.OnStart()

	h.Bus().Subscribe(requests.IPToASNTopic, h.SendASNRequest)
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
		h.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", h.String(), url, err))
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		h.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
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
	if addr == "" {
		return
	}

	url := h.getASNURL(addr)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		h.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", h.String(), url, err))
		return
	}

	fields := strings.Split(page, ",")
	if len(fields) < 4 {
		h.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: Failed to parse the response", h.String(), url))
		return
	}

	asn, err := strconv.Atoi(strings.Trim(fields[1], "\""))
	if err != nil {
		h.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to parse the origin response: %v", h.String(), url, err),
		)
		return
	}

	h.Bus().Publish(requests.NewASNTopic, &requests.ASNRequest{
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
