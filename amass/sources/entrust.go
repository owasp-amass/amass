// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/caffix/amass/amass/internal/utils"
)

const (
	EntrustSourceString string = "Entrust"
	entrustBaseURL      string = "http://ipv4info.com"
)

func EntrustQuery(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return []string{}
	}

	u, _ := url.Parse("https://ctsearch.entrust.com/api/v1/certificates")
	u.RawQuery = url.Values{
		"fields":         {"subjectO,issuerDN,subjectDN,signAlg,san,sn,subjectCNReversed,cert"},
		"domain":         {domain},
		"includeExpired": {"true"},
		"exactMatch":     {"false"},
		"limit":          {"5000"},
	}.Encode()

	page := utils.GetWebPage(u.String(), nil)
	if page == "" {
		return unique
	}
	content := strings.Replace(page, "u003d", " ", -1)

	re := utils.SubdomainRegex(domain)
	for _, sd := range re.FindAllString(content, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}

	for _, name := range entrustExtractReversedSubmatches(page) {
		match := re.FindString(name)
		if match != "" {
			if u := utils.NewUniqueElements(unique, match); len(u) > 0 {
				unique = append(unique, u...)
			}
		}
	}
	return unique
}

func entrustExtractReversedSubmatches(content string) []string {
	var rev, results []string

	re := regexp.MustCompile("\"valueReversed\": \"(.*)\"")
	for _, subs := range re.FindAllStringSubmatch(content, -1) {
		rev = append(rev, strings.TrimSpace(subs[1]))
	}

	for _, r := range rev {
		s := entrustReverseSubdomain(r)

		results = append(results, removeAsteriskLabel(s))
	}
	return results
}

func entrustReverseSubdomain(name string) string {
	var result []string

	s := strings.Split(name, "")
	for i := len(s) - 1; i >= 0; i-- {
		result = append(result, s[i])
	}
	return strings.Join(result, "")
}

func removeAsteriskLabel(s string) string {
	var index int

	labels := strings.Split(s, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		if strings.TrimSpace(labels[i]) == "*" {
			break
		}
		index = i
	}
	if index == len(labels)-1 {
		return ""
	}
	return strings.Join(labels[index:], ".")
}
