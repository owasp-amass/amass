// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/service"
	"github.com/caffix/stringset"
)

// ViewDNS is the Service that handles access to the ViewDNS data source.
type ViewDNS struct {
	service.BaseService

	SourceType string
}

// NewViewDNS returns he object initialized, but not yet started.
func NewViewDNS(sys systems.System) *ViewDNS {
	v := &ViewDNS{SourceType: requests.SCRAPE}

	v.BaseService = *service.NewBaseService(v, "ViewDNS")
	return v
}

// Description implements the Service interface.
func (v *ViewDNS) Description() string {
	return v.SourceType
}

// OnStart implements the Service interface.
func (v *ViewDNS) OnStart() error {
	v.SetRateLimit(1)
	return nil
}

// OnRequest implements the Service interface.
func (v *ViewDNS) OnRequest(ctx context.Context, args service.Args) {
	if req, ok := args.(*requests.DNSRequest); ok {
		v.dnsRequest(ctx, req)
	}
}

func (v *ViewDNS) dnsRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return
	}

	if !cfg.IsDomainInScope(req.Domain) {
		return
	}

	numRateLimitChecks(v, 9)
	bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
		fmt.Sprintf("Querying %s for %s subdomains", v.String(), req.Domain))

	var unique []string
	u := v.getIPHistoryURL(req.Domain)
	// The ViewDNS IP History lookup sometimes reveals interesting results
	page, err := http.RequestWebPage(ctx, u, nil, nil, nil)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", v.String(), u, err))
		return
	}

	// Look for IP addresses in the web page returned
	re := regexp.MustCompile(net.IPv4RE)
	for _, sd := range re.FindAllString(page, -1) {
		addr := NewUniqueElements(unique, sd)

		if len(addr) > 0 {
			bus.Publish(requests.NewAddrTopic, eventbus.PriorityHigh, &requests.AddrRequest{
				Address: addr[0],
				Domain:  req.Domain,
				Tag:     v.SourceType,
				Source:  v.String(),
			})
		}
	}
}

// OnWhoisRequest implements the Service interface.
func (v *ViewDNS) OnWhoisRequest(ctx context.Context, req *requests.WhoisRequest) {
	cfg, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return
	}

	if !cfg.IsDomainInScope(req.Domain) {
		return
	}

	numRateLimitChecks(v, 9)
	u := v.getReverseWhoisURL(req.Domain)
	page, err := http.RequestWebPage(ctx, u, nil, nil, nil)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", v.String(), u, err))
		return
	}
	// Pull the table we need from the page content
	table := getViewDNSTable(page)
	if table == "" {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: Failed to discover the table of results", v.String(), u),
		)
		return
	}
	// Get the list of domain names discovered through the reverse DNS service
	re := regexp.MustCompile("<tr><td>([a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1}[.]{1}[a-zA-Z0-9-]+)</td><td>")
	subs := re.FindAllStringSubmatch(table, -1)

	matches := stringset.New()
	for _, match := range subs {
		sub := match[1]
		if sub != "" {
			matches.Insert(strings.TrimSpace(sub))
		}
	}

	if len(matches) > 0 {
		bus.Publish(requests.NewWhoisTopic, eventbus.PriorityHigh, &requests.WhoisRequest{
			Domain:     req.Domain,
			NewDomains: matches.Slice(),
			Tag:        v.SourceType,
			Source:     v.String(),
		})
	}
}

func getViewDNSTable(page string) string {
	var begin, end int

	s := page
	for i := 0; i < 4; i++ {
		b := strings.Index(s, "<table")
		if b == -1 {
			return ""
		}
		begin += b + 6

		if e := strings.Index(s[b:], "</table>"); e != -1 {
			end = begin + e
		} else {
			return ""
		}
		s = page[end+8:]
	}
	i := strings.Index(page[begin:end], "<table")
	i = strings.Index(page[begin+i+6:end], "<table")
	return page[begin+i : end]
}

func (v *ViewDNS) getReverseWhoisURL(domain string) string {
	format := "https://viewdns.info/reversewhois/?q=%s"
	return fmt.Sprintf(format, domain)
}

func (v *ViewDNS) getIPHistoryURL(domain string) string {
	format := "https://viewdns.info/iphistory/?domain=%s"
	return fmt.Sprintf(format, domain)
}

// NewUniqueElements removes elements that have duplicates in the original or new elements.
func NewUniqueElements(orig []string, add ...string) []string {
	var n []string

	for _, av := range add {
		found := false
		s := strings.ToLower(av)

		// Check the original slice for duplicates
		for _, ov := range orig {
			if s == strings.ToLower(ov) {
				found = true
				break
			}
		}
		// Check that we didn't already add it in
		if !found {
			for _, nv := range n {
				if s == nv {
					found = true
					break
				}
			}
		}
		// If no duplicates were found, add the entry in
		if !found {
			n = append(n, s)
		}
	}
	return n
}
