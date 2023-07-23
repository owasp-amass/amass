// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/caffix/pipeline"
	"github.com/caffix/service"
	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v4/datasrcs"
	amassnet "github.com/owasp-amass/amass/v4/net"
	"github.com/owasp-amass/amass/v4/requests"
	"github.com/owasp-amass/amass/v4/systems"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/resolve"
	bf "github.com/tylertreat/BoomFilters"
	"golang.org/x/net/publicsuffix"
)

const (
	maxDnsPipelineTasks    int = 2000
	maxActivePipelineTasks int = 50
)

// Collection is the object type used to execute a open source information gathering with Amass.
type Collection struct {
	sync.Mutex
	Config            *config.Config
	Sys               systems.System
	ctx               context.Context
	srcs              []service.Service
	Output            chan *requests.Output
	done              chan struct{}
	doneAlreadyClosed bool
	filter            *bf.StableBloomFilter
	timeChan          chan time.Time
}

// NewCollection returns an initialized Collection object that has not been started yet.
func NewCollection(cfg *config.Config, sys systems.System) *Collection {
	return &Collection{
		Config:   cfg,
		Sys:      sys,
		srcs:     datasrcs.SelectedDataSources(cfg, sys.DataSources()),
		Output:   make(chan *requests.Output, 100),
		done:     make(chan struct{}, 2),
		filter:   bf.NewDefaultStableBloomFilter(1000000, 0.01),
		timeChan: make(chan time.Time, 50),
	}
}

// Done safely closes the done broadcast channel.
func (c *Collection) Done() {
	c.Lock()
	defer c.Unlock()

	if !c.doneAlreadyClosed {
		c.doneAlreadyClosed = true
		close(c.done)
	}
}

// HostedDomains uses open source intelligence to discover root domain names in the target infrastructure.
func (c *Collection) HostedDomains(ctx context.Context) error {
	if c.Output == nil {
		return errors.New("the intelligence collection did not have an output channel")
	} else if err := c.Config.CheckSettings(); err != nil {
		return err
	}

	defer close(c.Output)
	// Setup the context used throughout the collection
	var cancel context.CancelFunc
	c.ctx, cancel = context.WithCancel(ctx)
	defer cancel()

	var stages []pipeline.Stage
	stages = append(stages, pipeline.DynamicPool("", c.makeDNSTaskFunc(), maxDnsPipelineTasks))
	if c.Config.Active {
		stages = append(stages, pipeline.FIFO("", newActiveTask(c, maxActivePipelineTasks)))
	}
	stages = append(stages, pipeline.FIFO("filter", c.makeFilterTaskFunc()))

	// Send IP addresses to the input source to scan for domain names
	source := newIntelSource(c)
	for _, addr := range c.Config.Scope.Addresses {
		source.InputAddress(&requests.AddrRequest{Address: addr.String()})
	}
	for _, cidr := range append(c.Config.Scope.CIDRs, c.asnsToCIDRs()...) {
		// Skip IPv6 netblocks, since they are simply too large
		if ip := cidr.IP.Mask(cidr.Mask); amassnet.IsIPv6(ip) {
			continue
		}

		for _, addr := range amassnet.AllHosts(cidr) {
			source.InputAddress(&requests.AddrRequest{Address: addr.String()})
		}
	}

	return pipeline.NewPipeline(stages...).Execute(ctx, source, c.makeOutputSink())
}

func (c *Collection) makeOutputSink() pipeline.SinkFunc {
	return pipeline.SinkFunc(func(ctx context.Context, data pipeline.Data) error {
		if out, ok := data.(*requests.Output); ok && out != nil {
			c.Output <- out
		}
		return nil
	})
}

func (c *Collection) makeDNSTaskFunc() pipeline.TaskFunc {
	return pipeline.TaskFunc(func(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
		select {
		case <-ctx.Done():
			return nil, nil
		default:
		}

		req, ok := data.(*requests.AddrRequest)
		if !ok {
			return data, nil
		}
		if req == nil {
			return nil, nil
		}

		ip := net.ParseIP(req.Address)
		if ip == nil {
			return nil, nil
		}

		msg := resolve.ReverseMsg(req.Address)
		if msg == nil {
			return nil, nil
		}

		addrinfo := requests.AddressInfo{Address: ip}
		resp, err := c.Sys.TrustedResolvers().QueryBlocking(ctx, msg)
		if err == nil {
			ans := resolve.ExtractAnswers(resp)

			if len(ans) > 0 {
				d := strings.TrimSpace(resolve.FirstProperSubdomain(c.ctx, c.Sys.TrustedResolvers(), ans[0].Data))

				if d != "" {
					go pipeline.SendData(ctx, "filter", &requests.Output{
						Name:      d,
						Domain:    d,
						Addresses: []requests.AddressInfo{addrinfo},
					}, tp)
				}
			}
		}
		return data, nil
	})
}

func (c *Collection) makeFilterTaskFunc() pipeline.TaskFunc {
	return pipeline.TaskFunc(func(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
		select {
		case <-ctx.Done():
			return nil, nil
		default:
		}

		if req, ok := data.(*requests.Output); ok && req != nil && !c.filter.TestAndAdd([]byte(req.Domain)) {
			return data, nil
		}
		return nil, nil
	})
}

func (c *Collection) asnsToCIDRs() []*net.IPNet {
	var cidrs []*net.IPNet

	if len(c.Config.Scope.ASNs) == 0 {
		return cidrs
	}

	cidrSet := stringset.New()
	defer cidrSet.Close()

	for _, asn := range c.Config.Scope.ASNs {
		req := c.Sys.Cache().ASNSearch(asn)

		if req == nil {
			systems.PopulateCache(c.ctx, asn, c.Sys)
			req = c.Sys.Cache().ASNSearch(asn)
			if req == nil {
				continue
			}
		}

		cidrSet.InsertMany(req.Netblocks...)
	}

	filter := bf.NewDefaultStableBloomFilter(1000000, 0.01)
	defer filter.Reset()

	// Do not return CIDRs that are already in the config
	for _, cidr := range c.Config.Scope.CIDRs {
		filter.Add([]byte(cidr.String()))
	}

	for _, netblock := range cidrSet.Slice() {
		_, ipnet, err := net.ParseCIDR(netblock)

		if err == nil && !filter.Test([]byte(ipnet.String())) {
			cidrs = append(cidrs, ipnet)
		}
	}

	return cidrs
}

// ReverseWhois returns domain names that are related to the domains provided
func (c *Collection) ReverseWhois() error {
	if err := c.Config.CheckSettings(); err != nil {
		return err
	}

	go func() {
		for {
			for _, src := range c.srcs {
				select {
				case req := <-src.Output():
					if w, ok := req.(*requests.WhoisRequest); ok {
						c.collect(w)
					}
				default:
				}
			}
		}
	}()
	// Send the whois requests to the data sources
	for _, src := range c.srcs {
		for _, domain := range c.Config.Domains() {
			src.Input() <- &requests.WhoisRequest{Domain: domain}
		}
	}

	last := time.Now()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case <-c.done:
			break loop
		case l := <-c.timeChan:
			if l.After(last) {
				last = l
			}
		case now := <-t.C:
			if now.Sub(last) > 15*time.Second {
				break loop
			}
		}
	}
	close(c.Output)
	return nil
}

func (c *Collection) collect(req *requests.WhoisRequest) {
	c.timeChan <- time.Now()

	for _, name := range req.NewDomains {
		if d, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil && !c.filter.TestAndAdd([]byte(d)) {
			c.Output <- &requests.Output{
				Name:   d,
				Domain: d,
			}
		}
	}
}
