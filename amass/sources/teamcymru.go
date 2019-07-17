// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	eb "github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
)

// TeamCymru is the Service that handles access to the TeamCymru data source.
type TeamCymru struct {
	core.BaseService

	SourceType string
	RateLimit  time.Duration
}

// NewTeamCymru returns he object initialized, but not yet started.
func NewTeamCymru(config *core.Config, bus *eb.EventBus) *TeamCymru {
	t := &TeamCymru{
		SourceType: core.API,
		RateLimit:  100 * time.Millisecond,
	}

	t.BaseService = *core.NewBaseService(t, "TeamCymru", config, bus)
	return t
}

// OnStart implements the Service interface
func (t *TeamCymru) OnStart() error {
	t.BaseService.OnStart()

	t.Bus().Subscribe(core.IPToASNTopic, t.SendASNRequest)
	go t.processRequests()
	return nil
}

func (t *TeamCymru) processRequests() {
	last := time.Now().Truncate(10 * time.Minute)

	for {
		select {
		case <-t.Quit():
			return
		case req := <-t.ASNRequestChan():
			if time.Now().Sub(last) < t.RateLimit {
				time.Sleep(t.RateLimit)
			}
			last = time.Now()
			t.executeQuery(req.Address)
			last = time.Now()
		case <-t.DNSRequestChan():
		case <-t.AddrRequestChan():
		case <-t.WhoisRequestChan():
		}
	}
}

func (t *TeamCymru) executeQuery(addr string) {
	if addr == "" {
		return
	}

	t.SetActive()
	req := t.origin(addr)
	if req == nil {
		return
	}

	asn := t.asnLookup(req.ASN)
	if asn == nil {
		return
	}

	req.AllocationDate = asn.AllocationDate
	req.Description = asn.Description
	t.Bus().Publish(core.NewASNTopic, req)
}

func (t *TeamCymru) origin(addr string) *core.ASNRequest {
	var err error
	var name string
	var answers []core.DNSAnswer
	if ip := net.ParseIP(addr); utils.IsIPv4(ip) {
		name = utils.ReverseIP(addr) + ".origin.asn.cymru.com"
	} else if utils.IsIPv6(ip) {
		name = utils.IPv6NibbleFormat(utils.HexString(ip)) + ".origin6.asn.cymru.com"
	} else {
		t.Config().Log.Printf("%s: %s: Failed to parse the IP address", t.String(), addr)
		return nil
	}

	answers, err = core.Resolve(name, "TXT", core.PriorityHigh)
	if err != nil {
		t.Config().Log.Printf("%s: %s: DNS TXT record query error: %v", t.String(), name, err)
		return nil
	}

	fields := strings.Split(answers[0].Data, " | ")
	if len(fields) < 5 {
		t.Config().Log.Printf("%s: %s: Failed to parse the origin response", t.String(), name)
		return nil
	}

	asn, err := strconv.Atoi(strings.TrimSpace(fields[0]))
	if err != nil {
		t.Config().Log.Printf("%s: %s: Failed to parse the origin response: %v", t.String(), name, err)
		return nil
	}

	at, err := time.Parse("2006-Jan-02", strings.TrimSpace(fields[4]))
	if err != nil {
		at = time.Now()
	}

	return &core.ASNRequest{
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

func (t *TeamCymru) asnLookup(asn int) *core.ASNRequest {
	var err error
	var answers []core.DNSAnswer
	name := "AS" + strconv.Itoa(asn) + ".asn.cymru.com"

	answers, err = core.Resolve(name, "TXT", core.PriorityHigh)
	if err != nil {
		t.Config().Log.Printf("%s: %s: DNS TXT record query error: %v", t.String(), name, err)
		return nil
	}

	fields := strings.Split(answers[0].Data, " | ")
	if len(fields) < 5 {
		t.Config().Log.Printf("%s: %s: Failed to parse the origin response", t.String(), name)
		return nil
	}

	pASN, err := strconv.Atoi(strings.TrimSpace(fields[0]))
	if err != nil || asn != pASN {
		t.Config().Log.Printf("%s: %s: Failed to parse the origin response: %v", t.String(), name, err)
		return nil
	}

	at, err := time.Parse("2006-Jan-02", strings.TrimSpace(fields[3]))
	if err != nil {
		at = time.Now()
	}

	return &core.ASNRequest{
		ASN:            asn,
		CC:             strings.TrimSpace(fields[1]),
		Registry:       strings.TrimSpace(fields[2]),
		AllocationDate: at,
		Description:    strings.TrimSpace(fields[4]),
		Tag:            t.SourceType,
		Source:         t.String(),
	}
}
