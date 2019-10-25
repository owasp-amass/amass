// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"fmt"
	"time"
	outhttp "net/http"
	"net"
	"net/url"
	"strings"
	"io/ioutil"

	"github.com/OWASP/Amass/config"
	"github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
)

// PTRArchive is the Service that handles access to the Exalead data source.
type PTRArchive struct {
	BaseService

	SourceType string
}

// NewPTRArchive returns he object initialized, but not yet started.
func NewPTRArchive(sys System) *PTRArchive {
	p := &PTRArchive{SourceType: requests.SCRAPE}

	p.BaseService = *NewBaseService(p, "PTRArchive", sys)
	return p
}

// Type implements the Service interface.
func (p *PTRArchive) Type() string {
	return p.SourceType
}

// OnStart implements the Service interface.
func (p *PTRArchive) OnStart() error {
	p.BaseService.OnStart()

	p.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (p *PTRArchive) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	p.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, p.String())

	v := url.Values{}
	v.Set("name", "Ava")

	dial := net.Dialer{}
	client := &outhttp.Client{
		Transport: &outhttp.Transport{
			DialContext:         dial.DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	url := p.getURL(req.Domain)

	request, err := outhttp.NewRequest("GET", url, strings.NewReader(v.Encode()))

	cookie := &outhttp.Cookie{
		Name:   "test",
		Domain: "ptrarchive.com",
		Value:  "123432",
	}
	request.AddCookie(cookie)

	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: Failed to setup the POST request: %v", p.String(), err))
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", "https://ptrarchive.com")

	resp, err := client.Do(request)
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: The POST request failed: %v", p.String(), err))
	}

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	

	for _, sd := range re.FindAllString(string(in), -1) {
		name := cleanName(sd)
		if name == "automated_programs_unauthorized."+req.Domain {
			continue
		}

		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   name,
			Domain: req.Domain,
			Tag:    p.SourceType,
			Source: p.String(),
		})
	}
}

func (p *PTRArchive) getURL(domain string) string {
	format := "http://ptrarchive.com/tools/search4.htm?label=%s&date=ALL"

	return fmt.Sprintf(format, domain)
}
