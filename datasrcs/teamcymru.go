// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/eventbus"
	amassnet "github.com/OWASP/Amass/v3/net"
	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/OWASP/Amass/v3/stringset"
	"github.com/OWASP/Amass/v3/systems"
)

// TeamCymru is the Service that handles access to the TeamCymru data source.
type TeamCymru struct {
	requests.BaseService

	SourceType string
	sys        systems.System
}

// NewTeamCymru returns he object initialized, but not yet started.
func NewTeamCymru(sys systems.System) *TeamCymru {
	t := &TeamCymru{
		SourceType: requests.API,
		sys:        sys,
	}

	t.BaseService = *requests.NewBaseService(t, "TeamCymru")
	return t
}

// Type implements the Service interface.
func (t *TeamCymru) Type() string {
	return t.SourceType
}

// OnStart implements the Service interface.
func (t *TeamCymru) OnStart() error {
	t.BaseService.OnStart()

	t.SetRateLimit(time.Second)
	return nil
}

// OnASNRequest implements the Service interface.
func (t *TeamCymru) OnASNRequest(ctx context.Context, req *requests.ASNRequest) {
	_, bus, err := ContextConfigBus(ctx)
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
	_, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return nil
	}

	var name string
	var answers []requests.DNSAnswer
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

	answers, err = t.sys.Pool().Resolve(ctx, name, "TXT", resolvers.PriorityCritical, resolvers.RetryPolicy)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: DNS TXT record query error: %v", t.String(), name, err),
		)
		return nil
	}

	fields := strings.Split(answers[0].Data, " | ")
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
		Netblocks:      stringset.New(strings.TrimSpace(fields[1])),
		Tag:            t.SourceType,
		Source:         t.String(),
	}
}

func (t *TeamCymru) asnLookup(ctx context.Context, asn int) *requests.ASNRequest {
	_, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return nil
	}

	var answers []requests.DNSAnswer
	name := "AS" + strconv.Itoa(asn) + ".asn.cymru.com"

	answers, err = t.sys.Pool().Resolve(ctx, name, "TXT", resolvers.PriorityCritical, resolvers.RetryPolicy)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: DNS TXT record query error: %v", t.String(), name, err),
		)
		return nil
	}

	fields := strings.Split(answers[0].Data, " | ")
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
