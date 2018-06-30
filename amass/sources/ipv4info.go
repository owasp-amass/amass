// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"regexp"
	"time"

	"github.com/caffix/amass/amass/internal/utils"
)

type IPv4Info struct {
	BaseDataSource
	baseURL string
}

func NewIPv4Info() DataSource {
	i := &IPv4Info{baseURL: "http://ipv4info.com"}

	i.BaseDataSource = *NewBaseDataSource(SCRAPE, "IPv4info")
	return i
}

func (i *IPv4Info) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return []string{}
	}

	url := i.getURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		i.Log(fmt.Sprintf("%s: %v", url, err))
		return unique
	}
	time.Sleep(1 * time.Second)

	url = i.ipSubmatch(page, domain)
	page, err = utils.GetWebPage(url, nil)
	if err != nil {
		i.Log(fmt.Sprintf("%s: %v", url, err))
		return unique
	}
	time.Sleep(1 * time.Second)

	url = i.domainSubmatch(page, domain)
	page, err = utils.GetWebPage(url, nil)
	if err != nil {
		i.Log(fmt.Sprintf("%s: %v", url, err))
		return unique
	}
	time.Sleep(1 * time.Second)

	url = i.subdomainSubmatch(page, domain)
	page, err = utils.GetWebPage(url, nil)
	if err != nil {
		i.Log(fmt.Sprintf("%s: %v", url, err))
		return unique
	}

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
