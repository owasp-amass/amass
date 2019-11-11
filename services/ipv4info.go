// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// IPv4Info is the Service that handles access to the IPv4Info data source.
type IPv4Info struct {
	BaseService

	SourceType string
	baseURL    string
}

// NewIPv4Info returns he object initialized, but not yet started.
func NewIPv4Info(sys System) *IPv4Info {
	i := &IPv4Info{
		SourceType: requests.SCRAPE,
		baseURL:    "http://ipv4info.com",
	}

	i.BaseService = *NewBaseService(i, "IPv4Info", sys)
	return i
}

// Type implements the Service interface.
func (i *IPv4Info) Type() string {
	return i.SourceType
}

// OnStart implements the Service interface.
func (i *IPv4Info) OnStart() error {
	i.BaseService.OnStart()

	i.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (i *IPv4Info) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	i.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, i.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", i.String(), req.Domain))

	url := i.getURL(req.Domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", i.String(), url, err))
		return
	}

	i.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, i.String())

	url = i.ipSubmatch(page, req.Domain)
	page, err = http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", i.String(), url, err))
		return
	}

	i.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, i.String())

	url = i.domainSubmatch(page, req.Domain)
	page, err = http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", i.String(), url, err))
		return
	}

	i.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, i.String())

	url = i.subdomainSubmatch(page, req.Domain)
	page, err = http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", i.String(), url, err))
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(sd),
			Domain: req.Domain,
			Tag:    i.SourceType,
			Source: i.String(),
		})
	}
}

func (i *IPv4Info) ipSubmatch(content, domain string) string {
	re := regexp.MustCompile("/ip-address/(.*)/" + domain)
	subs := re.FindAllString(content, -1)
	if len(subs) == 0 {
		return ""
	}
	return i.baseURL + subs[0]
}

func (i *IPv4Info) domainSubmatch(content, domain string) string {
	re := regexp.MustCompile("/dns/(.*?)/" + domain)
	subs := re.FindAllString(content, -1)
	if len(subs) == 0 {
		return ""
	}
	return i.baseURL + subs[0]
}

func (i *IPv4Info) subdomainSubmatch(content, domain string) string {
	re := regexp.MustCompile("/subdomains/(.*?)/" + domain)
	subs := re.FindAllString(content, -1)
	if len(subs) == 0 {
		return ""
	}
	return i.baseURL + subs[0]
}

func (i *IPv4Info) getURL(domain string) string {
	format := i.baseURL + "/search/%s"

	return fmt.Sprintf(format, domain)
}
