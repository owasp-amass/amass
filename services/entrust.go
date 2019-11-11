// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// Entrust is the Service that handles access to the Entrust data source.
type Entrust struct {
	BaseService

	SourceType string
}

// NewEntrust returns he object initialized, but not yet started.
func NewEntrust(sys System) *Entrust {
	e := &Entrust{SourceType: requests.CERT}

	e.BaseService = *NewBaseService(e, "Entrust", sys)
	return e
}

// Type implements the Service interface.
func (e *Entrust) Type() string {
	return e.SourceType
}

// OnStart implements the Service interface.
func (e *Entrust) OnStart() error {
	e.BaseService.OnStart()

	e.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (e *Entrust) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	e.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, e.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", e.String(), req.Domain))

	u := e.getURL(req.Domain)
	page, err := http.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", e.String(), u, err))
		return
	}
	content := strings.Replace(page, "u003d", " ", -1)

	for _, sd := range re.FindAllString(content, -1) {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(sd),
			Domain: req.Domain,
			Tag:    e.SourceType,
			Source: e.String(),
		})
	}

	for _, name := range e.extractReversedSubmatches(page) {
		if match := re.FindString(name); match != "" {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   cleanName(match),
				Domain: req.Domain,
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

		results = append(results, dns.RemoveAsteriskLabel(s))
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
