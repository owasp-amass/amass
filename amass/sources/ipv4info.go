// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"regexp"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// IPv4Info is the AmassService that handles access to the IPv4Info data source.
type IPv4Info struct {
	core.BaseAmassService

	baseURL    string
	SourceType string
}

// NewIPv4Info returns he object initialized, but not yet started.
func NewIPv4Info(e *core.Enumeration) *IPv4Info {
	i := &IPv4Info{
		baseURL:    "http://ipv4info.com",
		SourceType: core.SCRAPE,
	}

	i.BaseAmassService = *core.NewBaseAmassService(e, "IPv4Info", i)
	return i
}

// OnStart implements the AmassService interface
func (i *IPv4Info) OnStart() error {
	i.BaseAmassService.OnStart()

	go i.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (i *IPv4Info) OnStop() error {
	i.BaseAmassService.OnStop()
	return nil
}

func (i *IPv4Info) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range i.Enum().Config.Domains() {
		i.executeQuery(domain)
	}
}

func (i *IPv4Info) executeQuery(domain string) {
	url := i.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		i.Enum().Log.Printf("%s: %s: %v", i.String(), url, err)
		return
	}

	i.SetActive()
	time.Sleep(time.Second)
	url = i.ipSubmatch(page, domain)
	page, err = utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		i.Enum().Log.Printf("%s: %s: %v", i.String(), url, err)
		return
	}

	i.SetActive()
	time.Sleep(time.Second)
	url = i.domainSubmatch(page, domain)
	page, err = utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		i.Enum().Log.Printf("%s: %s: %v", i.String(), url, err)
		return
	}

	i.SetActive()
	time.Sleep(time.Second)
	url = i.subdomainSubmatch(page, domain)
	page, err = utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		i.Enum().Log.Printf("%s: %s: %v", i.String(), url, err)
		return
	}

	re := i.Enum().Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		req := &core.AmassRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    i.SourceType,
			Source: i.String(),
		}

		if i.Enum().DupDataSourceName(req) {
			continue
		}
		i.Enum().Bus.Publish(core.NEWNAME, req)
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
