// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"bufio"
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
)

const (
	// ShadowServerWhoisURL is the URL for the ShadowServer whois server.
	ShadowServerWhoisURL = "asn.shadowserver.org"
)

// ShadowServer is the Service that handles access to the ShadowServer data source.
type ShadowServer struct {
	BaseService

	SourceType string
	addr       string
}

// NewShadowServer returns he object initialized, but not yet started.
func NewShadowServer(sys System) *ShadowServer {
	s := &ShadowServer{SourceType: requests.API}

	s.BaseService = *NewBaseService(s, "ShadowServer", sys)
	return s
}

// Type implements the Service interface.
func (s *ShadowServer) Type() string {
	return s.SourceType
}

// OnStart implements the Service interface.
func (s *ShadowServer) OnStart() error {
	s.BaseService.OnStart()

	if answers, _, err := s.System().Pool().Resolve(context.TODO(),
		ShadowServerWhoisURL, "A", resolvers.PriorityCritical); err == nil {
		ip := answers[0].Data
		if ip != "" {
			s.addr = ip
		}
	}

	s.SetRateLimit(3 * time.Second)
	return nil
}

// OnASNRequest implements the Service interface.
func (s *ShadowServer) OnASNRequest(ctx context.Context, req *requests.ASNRequest) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	if req.Address == "" && req.ASN == 0 {
		return
	}

	s.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, s.String())

	if req.Address != "" {
		s.executeASNAddrQuery(ctx, req.Address)
		return
	}

	s.executeASNQuery(ctx, req.ASN)
}

func (s *ShadowServer) executeASNQuery(ctx context.Context, asn int) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	blocks := s.netblocks(ctx, asn)
	if len(blocks) == 0 {
		return
	}

	s.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, s.String())

	req := s.origin(ctx, strings.Trim(blocks.Slice()[0], "/"))
	if req == nil {
		return
	}

	req.Netblocks.Union(blocks)
	bus.Publish(requests.NewASNTopic, req)
}

func (s *ShadowServer) executeASNAddrQuery(ctx context.Context, addr string) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	req := s.origin(ctx, addr)
	if req == nil {
		return
	}

	s.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, s.String())

	req.Netblocks.Union(s.netblocks(ctx, req.ASN))
	bus.Publish(requests.NewASNTopic, req)
}

func (s *ShadowServer) origin(ctx context.Context, addr string) *requests.ASNRequest {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return nil
	}

	if ip := net.ParseIP(addr); ip == nil || !amassnet.IsIPv4(ip) {
		return nil
	}
	name := amassdns.ReverseIP(addr) + ".origin.asn.shadowserver.org"

	answers, _, err := s.System().Pool().Resolve(ctx, name, "TXT", resolvers.PriorityCritical)
	if err != nil {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: DNS TXT record query error: %v", s.String(), name, err),
		)
		return nil
	}

	fields := strings.Split(strings.Trim(answers[0].Data, "\""), " | ")
	if len(fields) < 5 {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to parse the origin response", s.String(), name),
		)
		return nil
	}

	asn, err := strconv.Atoi(strings.TrimSpace(fields[0]))
	if err != nil {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to parse the origin response: %v", s.String(), name, err),
		)
		return nil
	}

	return &requests.ASNRequest{
		Address:     addr,
		ASN:         asn,
		Prefix:      strings.TrimSpace(fields[1]),
		CC:          strings.TrimSpace(fields[3]),
		Description: strings.TrimSpace(fields[2]) + " - " + strings.TrimSpace(fields[4]),
		Netblocks:   stringset.New(strings.TrimSpace(fields[1])),
		Tag:         s.SourceType,
		Source:      s.String(),
	}
}

func (s *ShadowServer) netblocks(ctx context.Context, asn int) stringset.Set {
	netblocks := stringset.New()

	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return netblocks
	}

	if s.addr == "" {
		answers, _, err := s.System().Pool().Resolve(ctx, ShadowServerWhoisURL, "A", resolvers.PriorityCritical)
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", s.String(), ShadowServerWhoisURL, err))
			return netblocks
		}

		ip := answers[0].Data
		if ip == "" {
			bus.Publish(requests.LogTopic,
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
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %v", s.String(), err))
		return netblocks
	}
	defer conn.Close()

	fmt.Fprintf(conn, "prefix %d\n", asn)
	scanner := bufio.NewScanner(conn)

	for scanner.Scan() {
		line := scanner.Text()

		if err := scanner.Err(); err == nil {
			netblocks.Insert(strings.TrimSpace(line))
		}
	}

	if len(netblocks) == 0 {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: Failed to acquire netblocks for ASN %d", s.String(), asn))
	}
	return netblocks
}
