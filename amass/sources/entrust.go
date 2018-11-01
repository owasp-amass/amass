// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// Entrust is data source object type that implements the DataSource interface.
type Entrust struct {
	BaseDataSource
}

// NewEntrust returns an initialized Entrust as a DataSource.
func NewEntrust(srv core.AmassService) DataSource {
	e := new(Entrust)

	e.BaseDataSource = *NewBaseDataSource(srv, core.CERT, "Entrust")
	return e
}

// Query returns the subdomain names discovered when querying this data source.
func (e *Entrust) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return []string{}
	}

	u := e.getURL(domain)
	page, err := utils.GetWebPage(u, nil)
	if err != nil {
		e.Service.Config().Log.Printf("%s: %v", u, err)
		return unique
	}
	content := strings.Replace(page, "u003d", " ", -1)

	e.Service.SetActive()
	re := utils.SubdomainRegex(domain)
	for _, sd := range re.FindAllString(content, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}

	for _, name := range e.extractReversedSubmatches(page) {
		e.Service.SetActive()
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

		results = append(results, utils.RemoveAsteriskLabel(s))
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
