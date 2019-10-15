// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/OWASP/Amass/config"
	"github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/miekg/dns"
)

// BruteForceQueryTypes contains the DNS record types that service queries for.
var BruteForceQueryTypes = []string{
	"CNAME",
	"A",
	"AAAA",
}

// BruteForceService is the Service that handles all brute force name generation
// within the architecture.
type BruteForceService struct {
	BaseService

	SourceType string
}

// NewBruteForceService returns he object initialized, but not yet started.
func NewBruteForceService(sys System) *BruteForceService {
	bfs := &BruteForceService{SourceType: requests.BRUTE}

	bfs.BaseService = *NewBaseService(bfs, "Brute Forcing", sys)
	return bfs
}

// Type implements the Service interface.
func (bfs *BruteForceService) Type() string {
	return bfs.SourceType
}

func (bfs *BruteForceService) goodRequest(cfg *config.Config, req *requests.DNSRequest) bool {
	if !cfg.IsDomainInScope(req.Name) {
		return false
	}

	if len(req.Records) == 0 {
		return true
	}

	var ok bool
	for _, r := range req.Records {
		t := uint16(r.Type)

		if t == dns.TypeA || t == dns.TypeAAAA {
			ok = true
			break
		}
	}
	return ok
}

// OnDNSRequest implements the Service interface.
func (bfs *BruteForceService) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if !bfs.goodRequest(cfg, req) {
		return
	}

	subdomain := strings.ToLower(req.Name)
	domain := strings.ToLower(req.Domain)
	wr := &requests.DNSRequest{
		Name:   subdomain,
		Domain: domain,
	}
	if subdomain == "" || domain == "" ||
		bfs.System().Pool().GetWildcardType(wr) == resolvers.WildcardTypeDynamic {
		return
	}

	var idx int
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-bfs.Quit():
			return
		case <-t.C:
			bus.Publish(requests.SetActiveTopic, bfs.String())
		default:
			if idx >= len(cfg.Wordlist) {
				return
			}
			bfs.System().Config().SemMaxDNSQueries.Acquire(1)
			word := strings.ToLower(cfg.Wordlist[idx])
			go bfs.bruteForceResolution(ctx, word, subdomain, domain)
			idx++
		}
	}
}

// OnSubdomainDiscovered implements the Service interface.
func (bfs *BruteForceService) OnSubdomainDiscovered(ctx context.Context, req *requests.DNSRequest, times int) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	if cfg == nil {
		return
	}

	if times == cfg.MinForRecursive {
		bfs.DNSRequest(ctx, req)
	}
}

func (bfs *BruteForceService) bruteForceResolution(ctx context.Context, word, sub, domain string) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	defer bfs.System().Config().SemMaxDNSQueries.Release(1)
	defer bus.Publish(requests.SetActiveTopic, bfs.String())

	if word == "" || sub == "" || domain == "" {
		return
	}

	name := word + "." + sub
	var answers []requests.DNSAnswer
	for _, t := range BruteForceQueryTypes {
		if a, _, err := bfs.System().Pool().Resolve(ctx, name, t, resolvers.PriorityLow); err == nil {
			answers = append(answers, a...)
			// Do not continue if a CNAME was discovered
			if t == "CNAME" {
				break
			}
		} else {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %v", bfs.String(), err))
		}
		bus.Publish(requests.SetActiveTopic, bfs.String())
	}
	if len(answers) == 0 {
		return
	}

	req := &requests.DNSRequest{
		Name:    name,
		Domain:  domain,
		Records: answers,
		Tag:     requests.BRUTE,
		Source:  bfs.String(),
	}

	if bfs.System().Pool().MatchesWildcard(req) {
		return
	}

	bus.Publish(requests.NameResolvedTopic, req)
}
