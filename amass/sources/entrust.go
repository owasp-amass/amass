// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/caffix/amass/amass/internal/utils"
)

type Entrust struct {
	BaseDataSource
}

func NewEntrust() DataSource {
	e := new(Entrust)

	e.BaseDataSource = *NewBaseDataSource(CERT, "Entrust")
	return e
}

func (e *Entrust) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return []string{}
	}

	u := e.getURL(domain)
	page, err := utils.GetWebPage(u, nil)
	if err != nil {
		e.Log(fmt.Sprintf("%s: %v", u, err))
		return unique
	}
	content := strings.Replace(page, "u003d", " ", -1)

	re := utils.SubdomainRegex(domain)
	for _, sd := range re.FindAllString(content, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}

	for _, name := range e.extractReversedSubmatches(page) {
		if match := re.FindString(name); match != "" {
			if u := utils.NewUniqueElements(unique, match); len(u) > 0 {
				unique = append(unique, u...)
			}
		}
	}
	return unique
}

func (e *Entrust) getURL(domain string) string {
	u, _ := url.Parse("https://ctsearch.entrust.com/api/v1/certificates")

	u.RawQuery = url.Values{
		"fields":         {"subjectO,issuerDN,subjectDN,signAlg,san,sn,subjectCNReversed,cert"},
		"domain":         {domain},
		"includeExpired": {"true"},
		"exactMatch":     {"false"},
		"limit":          {"5000"},
	}.Encode()
	return u.String()
}

func (e *Entrust) extractReversedSubmatches(content string) []string {
	var rev, results []string

	re := regexp.MustCompile("\"valueReversed\": \"(.*)\"")
	for _, subs := range re.FindAllStringSubmatch(content, -1) {
		rev = append(rev, strings.TrimSpace(subs[1]))
	}

	for _, r := range rev {
		s := e.reverseSubdomain(r)

		results = append(results, removeAsteriskLabel(s))
	}
	return results
}

func (e *Entrust) reverseSubdomain(name string) string {
	var result []string

	s := strings.Split(name, "")
	for i := len(s) - 1; i >= 0; i-- {
		result = append(result, s[i])
	}
	return strings.Join(result, "")
}
