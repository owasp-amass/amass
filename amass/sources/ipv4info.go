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

// IPv4Info is data source object type that implements the DataSource interface.
type IPv4Info struct {
	BaseDataSource
	baseURL string
}

// NewIPv4Info returns an initialized IPv4Info as a DataSource.
func NewIPv4Info(srv core.AmassService) DataSource {
	i := &IPv4Info{baseURL: "http://ipv4info.com"}

	i.BaseDataSource = *NewBaseDataSource(srv, core.SCRAPE, "IPv4info")
	return i
}

// Query returns the subdomain names discovered when querying this data source.
func (i *IPv4Info) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return []string{}
	}

	url := i.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		i.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	time.Sleep(time.Second)
	i.Service.SetActive()

	url = i.ipSubmatch(page, domain)
	page, err = utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		i.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	time.Sleep(time.Second)
	i.Service.SetActive()

	url = i.domainSubmatch(page, domain)
	page, err = utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		i.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	time.Sleep(time.Second)
	i.Service.SetActive()

	url = i.subdomainSubmatch(page, domain)
	page, err = utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		i.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	i.Service.SetActive()

	re := utils.SubdomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	return unique
}

func (i *IPv4Info) getURL(domain string) string {
	format := i.baseURL + "/search/%s"

	return fmt.Sprintf(format, domain)
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
