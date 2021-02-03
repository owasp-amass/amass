// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/service"
)

// IPv4Info is the Service that handles access to the IPv4Info data source.
type IPv4Info struct {
	service.BaseService

	SourceType string
	sys        systems.System
	baseURL    string
}

// NewIPv4Info returns he object initialized, but not yet started.
func NewIPv4Info(sys systems.System) *IPv4Info {
	i := &IPv4Info{
		SourceType: requests.SCRAPE,
		baseURL:    "http://ipv4info.com",
		sys:        sys,
	}

	i.BaseService = *service.NewBaseService(i, "IPv4Info")
	return i
}

// Description implements the Service interface.
func (i *IPv4Info) Description() string {
	return i.SourceType
}

// OnStart implements the Service interface.
func (i *IPv4Info) OnStart() error {
	i.SetRateLimit(1)
	return nil
}

// OnRequest implements the Service interface.
func (i *IPv4Info) OnRequest(ctx context.Context, args service.Args) {
	if req, ok := args.(*requests.AddrRequest); ok {
		i.addrRequest(ctx, req)
	}
}

func (i *IPv4Info) addrRequest(ctx context.Context, req *requests.AddrRequest) {
	cfg, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
		fmt.Sprintf("Querying %s for %s subdomains", i.String(), req.Domain))

	var url string
	var token string
	var count int
	for {
		url = i.getURL(req.Domain, token)
		page, err := http.RequestWebPage(ctx, url, nil, nil, nil)
		if err != nil {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", i.String(), url, err))
			return
		}

		for _, name := range re.FindAllString(page, -1) {
			genNewNameEvent(ctx, i.sys, i, name)
		}

		token = i.getToken(page, req.Domain)
		if count != 0 && !strings.Contains(token, strconv.Itoa(count)) {
			break
		}

		count++
	}
}

func (i *IPv4Info) getBaseToken(content, domain string) string {
	re := regexp.MustCompile("/dns/(.*?)/" + domain)
	results := re.FindAllString(content, -1)
	if len(results) == 0 {
		return ""
	}

	return strings.Split(results[0], "/")[2]
}

func (i *IPv4Info) getToken(content, domain string) string {
	re := regexp.MustCompile("/dns/(.*?)/" + domain)
	results := re.FindAllString(content, -1)
	if len(results) == 0 {
		re = regexp.MustCompile("/subdomains/(.*?)/" + domain + "\\.html")
		results = re.FindAllString(content, -1)

		if len(results) == 0 {
			return ""
		}
	}
	results = strings.Split(results[len(results) - 1], "/")

	if len(results) == 4 {
		return results[2]
	}
	return strings.Join(results[2:4], "/")
}

func (i *IPv4Info) getURL(domain string, token string) string {
	if token == "" {
		return i.baseURL + "/search/NF/" + domain
	}
	return i.baseURL + "/subdomains/" + token + "/" + domain
}
