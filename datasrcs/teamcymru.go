// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	amassnet "github.com/OWASP/Amass/v3/net"
	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/resolve"
	"github.com/caffix/service"
	"github.com/miekg/dns"
)

// TeamCymru is the Service that handles access to the TeamCymru data source.
type TeamCymru struct {
	service.BaseService

	SourceType string
	sys        systems.System
}

// NewTeamCymru returns he object initialized, but not yet started.
func NewTeamCymru(sys systems.System) *TeamCymru {
	t := &TeamCymru{
		SourceType: requests.API,
		sys:        sys,
	}

	t.BaseService = *service.NewBaseService(t, "TeamCymru")
	return t
}

// Description implements the Service interface.
func (t *TeamCymru) Description() string {
	return t.SourceType
}

// OnStart implements the Service interface.
func (t *TeamCymru) OnStart() error {
	t.SetRateLimit(1)
	return nil
}

// OnRequest implements the Service interface.
func (t *TeamCymru) OnRequest(ctx context.Context, args service.Args) {
	if req, ok := args.(*requests.ASNRequest); ok {
		t.asnRequest(ctx, req)
		t.CheckRateLimit()
	}
}

func (t *TeamCymru) asnRequest(ctx context.Context, req *requests.ASNRequest) {
	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	if req.Address == "" {
		return
	}

	t.CheckRateLimit()
	r := t.origin(ctx, req.Address)
	if r == nil {
		return
	}

	t.CheckRateLimit()
	asn := t.asnLookup(ctx, r.ASN)
	if asn == nil {
		return
	}

	r.AllocationDate = asn.AllocationDate
	r.Description = asn.Description
	bus.Publish(requests.NewASNTopic, eventbus.PriorityHigh, r)
}

func (t *TeamCymru) origin(ctx context.Context, addr string) *requests.ASNRequest {
	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return nil
	}

	var name string
	if ip := net.ParseIP(addr); amassnet.IsIPv4(ip) {
		name = amassdns.ReverseIP(addr) + ".origin.asn.cymru.com"
	} else if amassnet.IsIPv6(ip) {
		name = amassdns.IPv6NibbleFormat(ip.String()) + ".origin6.asn.cymru.com"
	} else {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: Failed to parse the IP address", t.String(), addr),
		)
		return nil
	}

	msg := resolve.QueryMsg(name, dns.TypeTXT)
	resp, err := t.sys.Pool().Query(ctx, msg, resolve.PriorityCritical, resolve.RetryPolicy)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: DNS TXT record query error: %v", t.String(), name, err),
		)
		return nil
	}

	ans := resolve.ExtractAnswers(resp)
	if len(ans) == 0 {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: DNS TXT record query returned zero answers", t.String(), name),
		)
		return nil
	}

	fields := strings.Split(ans[0].Data, " | ")
	if len(fields) < 5 {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: Failed to parse the origin response", t.String(), name),
		)
		return nil
	}

	asn, err := strconv.Atoi(strings.TrimSpace(fields[0]))
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: Failed to parse the origin response: %v", t.String(), name, err),
		)
		return nil
	}

	at, err := time.Parse("2006-Jan-02", strings.TrimSpace(fields[4]))
	if err != nil {
		at = time.Now()
	}

	return &requests.ASNRequest{
		Address:        addr,
		ASN:            asn,
		Prefix:         strings.TrimSpace(fields[1]),
		CC:             strings.TrimSpace(fields[2]),
		Registry:       strings.TrimSpace(fields[3]),
		AllocationDate: at,
		Netblocks:      []string{strings.TrimSpace(fields[1])},
		Tag:            t.SourceType,
		Source:         t.String(),
	}
}

func (t *TeamCymru) asnLookup(ctx context.Context, asn int) *requests.ASNRequest {
	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return nil
	}

	name := "AS" + strconv.Itoa(asn) + ".asn.cymru.com"
	msg := resolve.QueryMsg(name, dns.TypeTXT)

	resp, err := t.sys.Pool().Query(ctx, msg, resolve.PriorityCritical, resolve.RetryPolicy)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: DNS TXT record query error: %v", t.String(), name, err),
		)
		return nil
	}

	ans := resolve.ExtractAnswers(resp)
	if len(ans) == 0 {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: DNS TXT record query returned zero answers", t.String(), name),
		)
		return nil
	}

	fields := strings.Split(ans[0].Data, " | ")
	if len(fields) < 5 {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: Failed to parse the origin response", t.String(), name),
		)
		return nil
	}

	pASN, err := strconv.Atoi(strings.TrimSpace(fields[0]))
	if err != nil || asn != pASN {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: Failed to parse the origin response: %v", t.String(), name, err),
		)
		return nil
	}

	at, err := time.Parse("2006-Jan-02", strings.TrimSpace(fields[3]))
	if err != nil {
		at = time.Now()
	}

	return &requests.ASNRequest{
		ASN:            asn,
		CC:             strings.TrimSpace(fields[1]),
		Registry:       strings.TrimSpace(fields[2]),
		AllocationDate: at,
		Description:    strings.TrimSpace(fields[4]),
		Tag:            t.SourceType,
		Source:         t.String(),
	}
}
