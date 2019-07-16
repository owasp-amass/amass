// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
)

const (
	// ShadowServerWhoisURL is the URL for the ShadowServer whois server.
	ShadowServerWhoisURL = "asn.shadowserver.org"
)

// ShadowServer is the Service that handles access to the ShadowServer data source.
type ShadowServer struct {
	core.BaseService

	SourceType string
	RateLimit  time.Duration

	addr string
}

// NewShadowServer returns he object initialized, but not yet started.
func NewShadowServer(config *core.Config, bus *eventbus.EventBus) *ShadowServer {
	s := &ShadowServer{
		SourceType: core.API,
		RateLimit:  time.Second,
	}

	s.BaseService = *core.NewBaseService(s, "ShadowServer", config, bus)
	return s
}

// OnStart implements the Service interface
func (s *ShadowServer) OnStart() error {
	s.BaseService.OnStart()

	if answers, err := core.Resolve(ShadowServerWhoisURL, "A", core.PriorityHigh); err == nil {
		ip := answers[0].Data
		if ip != "" {
			s.addr = ip
		}
	}

	s.Bus().Subscribe(core.IPToASNTopic, s.SendASNRequest)
	go s.processRequests()
	return nil
}

func (s *ShadowServer) processRequests() {
	last := time.Now().Truncate(10 * time.Minute)
loop:
	for {
		select {
		case <-s.Quit():
			return
		case req := <-s.ASNRequestChan():
			if req.Address == "" && req.ASN == 0 {
				continue loop
			}
			if time.Now().Sub(last) < s.RateLimit {
				time.Sleep(s.RateLimit)
			}
			last = time.Now()
			if req.Address != "" {
				s.executeASNAddrQuery(req.Address)
			} else {
				s.executeASNQuery(req.ASN)
			}
			last = time.Now()
		case <-s.DNSRequestChan():
		case <-s.AddrRequestChan():
		case <-s.WhoisRequestChan():
		}
	}
}

func (s *ShadowServer) executeASNQuery(asn int) {
	s.SetActive()
	blocks := s.netblocks(asn)
	if len(blocks) == 0 {
		return
	}

	time.Sleep(s.RateLimit)
	req := s.origin(strings.Trim(blocks[0], "/"))
	if req == nil {
		return
	}

	req.Netblocks = utils.UniqueAppend(req.Netblocks, blocks...)
	s.Bus().Publish(core.NewASNTopic, req)
}

func (s *ShadowServer) executeASNAddrQuery(addr string) {
	s.SetActive()
	req := s.origin(addr)
	if req == nil {
		return
	}

	time.Sleep(s.RateLimit)
	req.Netblocks = utils.UniqueAppend(req.Netblocks, s.netblocks(req.ASN)...)
	s.Bus().Publish(core.NewASNTopic, req)
}

func (s *ShadowServer) origin(addr string) *core.ASNRequest {
	if ip := net.ParseIP(addr); ip == nil || !utils.IsIPv4(ip) {
		return nil
	}
	name := utils.ReverseIP(addr) + ".origin.asn.shadowserver.org"

	answers, err := core.Resolve(name, "TXT", core.PriorityHigh)
	if err != nil {
		s.Config().Log.Printf("%s: %s: DNS TXT record query error: %v", s.String(), name, err)
		return nil
	}

	fields := strings.Split(strings.Trim(answers[0].Data, "\""), " | ")
	if len(fields) < 5 {
		s.Config().Log.Printf("%s: %s: Failed to parse the origin response", s.String(), name)
		return nil
	}

	asn, err := strconv.Atoi(strings.TrimSpace(fields[0]))
	if err != nil {
		s.Config().Log.Printf("%s: %s: Failed to parse the origin response: %v", s.String(), name, err)
		return nil
	}

	return &core.ASNRequest{
		ASN:         asn,
		Prefix:      strings.TrimSpace(fields[1]),
		CC:          strings.TrimSpace(fields[3]),
		Description: strings.TrimSpace(fields[2]) + " - " + strings.TrimSpace(fields[4]),
		Netblocks:   []string{strings.TrimSpace(fields[1])},
		Tag:         s.SourceType,
		Source:      s.String(),
	}
}

func (s *ShadowServer) netblocks(asn int) []string {
	var netblocks []string

	if s.addr == "" {
		answers, err := core.Resolve(ShadowServerWhoisURL, "A", core.PriorityHigh)
		if err != nil {
			s.Config().Log.Printf("%s: %s: %v", s.String(), ShadowServerWhoisURL, err)
			return netblocks
		}

		ip := answers[0].Data
		if ip == "" {
			s.Config().Log.Printf("%s: Failed to resolve %s", s.String(), ShadowServerWhoisURL)
			return netblocks
		}
		s.addr = ip
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", s.addr+":43")
	if err != nil {
		s.Config().Log.Printf("%s: %v", s.String(), err)
		return netblocks
	}
	defer conn.Close()

	fmt.Fprintf(conn, "prefix %d\n", asn)
	scanner := bufio.NewScanner(conn)

	for scanner.Scan() {
		line := scanner.Text()

		if err := scanner.Err(); err == nil {
			netblocks = utils.UniqueAppend(netblocks, strings.TrimSpace(line))
		}
	}

	if len(netblocks) == 0 {
		s.Config().Log.Printf("%s: Failed to acquire netblocks for ASN %d", s.String(), asn)
	}
	return netblocks
}
