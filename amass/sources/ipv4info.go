// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"log"
	"regexp"

	"github.com/caffix/amass/amass/internal/utils"
)

const (
	IPv4InfoSourceString string = "IPv4info"
	ipv4infoBaseURL      string = "http://ipv4info.com"
)

func IPv4InfoQuery(domain, sub string, l *log.Logger) []string {
	var unique []string

	if domain != sub {
		return []string{}
	}

	url := ipv4infoURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		l.Printf("IPv4info error: %s: %v", url, err)
		return unique
	}

	url = ipv4infoIPSubmatch(page, domain)
	page, err = utils.GetWebPage(url, nil)
	if err != nil {
		l.Printf("IPv4info error: %s: %v", url, err)
		return unique
	}

	url = ipv4infoDomainSubmatch(page, domain)
	page, err = utils.GetWebPage(url, nil)
	if err != nil {
		l.Printf("IPv4info error: %s: %v", url, err)
		return unique
	}

	url = ipv4infoSubdomainSubmatch(page, domain)
	page, err = utils.GetWebPage(url, nil)
	if err != nil {
		l.Printf("IPv4info error: %s: %v", url, err)
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

func ipv4infoURL(domain string) string {
	format := ipv4infoBaseURL + "/search/%s"

	return fmt.Sprintf(format, domain)
}

func ipv4infoIPSubmatch(content, domain string) string {
	re := regexp.MustCompile("/ip-address/(.*)/" + domain)
	subs := re.FindAllString(content, -1)
	if len(subs) == 0 {
		return ""
	}
	return ipv4infoBaseURL + subs[0]
}

func ipv4infoDomainSubmatch(content, domain string) string {
	re := regexp.MustCompile("/dns/(.*?)/" + domain)
	subs := re.FindAllString(content, -1)
	if len(subs) == 0 {
		return ""
	}
	return ipv4infoBaseURL + subs[0]
}

func ipv4infoSubdomainSubmatch(content, domain string) string {
	re := regexp.MustCompile("/subdomains/(.*?)/" + domain)
	subs := re.FindAllString(content, -1)
	if len(subs) == 0 {
		return ""
	}
	return ipv4infoBaseURL + subs[0]
}
