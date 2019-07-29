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

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

const (
	// ShadowServerWhoisURL is the URL for the ShadowServer whois server.
	ShadowServerWhoisURL = "asn.shadowserver.org"
)

// ShadowServer is the Service that handles access to the ShadowServer data source.
type ShadowServer struct {
	services.BaseService

	SourceType string
	RateLimit  time.Duration

	addr string
}

// NewShadowServer returns he object initialized, but not yet started.
func NewShadowServer(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *ShadowServer {
	s := &ShadowServer{
		SourceType: requests.API,
		RateLimit:  time.Second,
	}

	s.BaseService = *services.NewBaseService(s, "ShadowServer", cfg, bus, pool)
	return s
}

// OnStart implements the Service interface
func (s *ShadowServer) OnStart() error {
	s.BaseService.OnStart()

	if answers, err := s.Pool().Resolve(ShadowServerWhoisURL, "A", resolvers.PriorityHigh); err == nil {
		ip := answers[0].Data
		if ip != "" {
			s.addr = ip
		}
	}

	s.Bus().Subscribe(requests.IPToASNTopic, s.SendASNRequest)
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
	s.Bus().Publish(requests.NewASNTopic, req)
}

func (s *ShadowServer) executeASNAddrQuery(addr string) {
	s.SetActive()
	req := s.origin(addr)
	if req == nil {
		return
	}

	time.Sleep(s.RateLimit)
	req.Netblocks = utils.UniqueAppend(req.Netblocks, s.netblocks(req.ASN)...)
	s.Bus().Publish(requests.NewASNTopic, req)
}

func (s *ShadowServer) origin(addr string) *requests.ASNRequest {
	if ip := net.ParseIP(addr); ip == nil || !utils.IsIPv4(ip) {
		return nil
	}
	name := utils.ReverseIP(addr) + ".origin.asn.shadowserver.org"

	answers, err := s.Pool().Resolve(name, "TXT", resolvers.PriorityHigh)
	if err != nil {
		s.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: DNS TXT record query error: %v", s.String(), name, err),
		)
		return nil
	}

	fields := strings.Split(strings.Trim(answers[0].Data, "\""), " | ")
	if len(fields) < 5 {
		s.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to parse the origin response", s.String(), name),
		)
		return nil
	}

	asn, err := strconv.Atoi(strings.TrimSpace(fields[0]))
	if err != nil {
		s.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to parse the origin response: %v", s.String(), name, err),
		)
		return nil
	}

	return &requests.ASNRequest{
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
		answers, err := s.Pool().Resolve(ShadowServerWhoisURL, "A", resolvers.PriorityHigh)
		if err != nil {
			s.Bus().Publish(requests.LogTopic,
				fmt.Sprintf("%s: %s: %v", s.String(), ShadowServerWhoisURL, err),
			)
			return netblocks
		}

		ip := answers[0].Data
		if ip == "" {
			s.Bus().Publish(requests.LogTopic,
				fmt.Sprintf("%s: Failed to resolve %s", s.String(), ShadowServerWhoisURL),
			)
			return netblocks
		}
		s.addr = ip
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", s.addr+":43")
	if err != nil {
		s.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %v", s.String(), err))
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
		s.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: Failed to acquire netblocks for ASN %d", s.String(), asn),
		)
	}
	return netblocks
}
