// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

// Entrust is the Service that handles access to the Entrust data source.
type Entrust struct {
	services.BaseService

	SourceType string
}

// NewEntrust returns he object initialized, but not yet started.
func NewEntrust(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *Entrust {
	e := &Entrust{SourceType: requests.CERT}

	e.BaseService = *services.NewBaseService(e, "Entrust", cfg, bus, pool)
	return e
}

// OnStart implements the Service interface
func (e *Entrust) OnStart() error {
	e.BaseService.OnStart()

	go e.processRequests()
	return nil
}

func (e *Entrust) processRequests() {
	for {
		select {
		case <-e.Quit():
			return
		case req := <-e.DNSRequestChan():
			if e.Config().IsDomainInScope(req.Domain) {
				e.executeQuery(req.Domain)
			}
		case <-e.AddrRequestChan():
		case <-e.ASNRequestChan():
		case <-e.WhoisRequestChan():
		}
	}
}

func (e *Entrust) executeQuery(domain string) {
	re := e.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	e.SetActive()
	u := e.getURL(domain)
	page, err := utils.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		e.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", e.String(), u, err))
		return
	}
	content := strings.Replace(page, "u003d", " ", -1)

	for _, sd := range re.FindAllString(content, -1) {
		e.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    e.SourceType,
			Source: e.String(),
		})
	}

	for _, name := range e.extractReversedSubmatches(page) {
		if match := re.FindString(name); match != "" {
			e.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   cleanName(match),
				Domain: domain,
				Tag:    e.SourceType,
				Source: e.String(),
			})
		}
	}
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
