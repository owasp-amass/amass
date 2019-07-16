// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"regexp"
	"time"

	"github.com/OWASP/Amass/amass/core"
	eb "github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
)

// IPv4Info is the Service that handles access to the IPv4Info data source.
type IPv4Info struct {
	core.BaseService

	baseURL    string
	SourceType string
}

// NewIPv4Info returns he object initialized, but not yet started.
func NewIPv4Info(config *core.Config, bus *eb.EventBus) *IPv4Info {
	i := &IPv4Info{
		baseURL:    "http://ipv4info.com",
		SourceType: core.SCRAPE,
	}

	i.BaseService = *core.NewBaseService(i, "IPv4Info", config, bus)
	return i
}

// OnStart implements the Service interface
func (i *IPv4Info) OnStart() error {
	i.BaseService.OnStart()

	go i.processRequests()
	return nil
}

func (i *IPv4Info) processRequests() {
	for {
		select {
		case <-i.Quit():
			return
		case req := <-i.DNSRequestChan():
			if i.Config().IsDomainInScope(req.Domain) {
				i.executeQuery(req.Domain)
			}
		case <-i.AddrRequestChan():
		case <-i.ASNRequestChan():
		case <-i.WhoisRequestChan():
		}
	}
}

func (i *IPv4Info) executeQuery(domain string) {
	re := i.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	url := i.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		i.Config().Log.Printf("%s: %s: %v", i.String(), url, err)
		return
	}

	i.SetActive()
	time.Sleep(time.Second)
	url = i.ipSubmatch(page, domain)
	page, err = utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		i.Config().Log.Printf("%s: %s: %v", i.String(), url, err)
		return
	}

	i.SetActive()
	time.Sleep(time.Second)
	url = i.domainSubmatch(page, domain)
	page, err = utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		i.Config().Log.Printf("%s: %s: %v", i.String(), url, err)
		return
	}

	i.SetActive()
	time.Sleep(time.Second)
	url = i.subdomainSubmatch(page, domain)
	page, err = utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		i.Config().Log.Printf("%s: %s: %v", i.String(), url, err)
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		i.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
			Name:   cleanName(sd),
			Domain: domain,
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
