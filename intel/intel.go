// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package intel

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/datasrcs"
	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/OWASP/Amass/v3/stringfilter"
	"github.com/OWASP/Amass/v3/systems"
	eb "github.com/caffix/eventbus"
	"github.com/caffix/pipeline"
	"github.com/caffix/service"
	"github.com/caffix/stringset"
	"github.com/miekg/dns"
)

// Collection is the object type used to execute a open source information gathering with Amass.
type Collection struct {
	sync.Mutex
	Config            *config.Config
	Bus               *eb.EventBus
	Sys               systems.System
	ctx               context.Context
	srcs              []service.Service
	Output            chan *requests.Output
	done              chan struct{}
	doneAlreadyClosed bool
	filter            stringfilter.Filter
}

// NewCollection returns an initialized Collection object that has not been started yet.
func NewCollection(cfg *config.Config, sys systems.System) *Collection {
	return &Collection{
		Config: cfg,
		Bus:    eb.NewEventBus(),
		Sys:    sys,
		srcs:   datasrcs.SelectedDataSources(cfg, sys.DataSources()),
		Output: make(chan *requests.Output, 100),
		done:   make(chan struct{}, 2),
		filter: stringfilter.NewStringFilter(),
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
		return errors.New("The intelligence collection did not have an output channel")
	} else if err := c.Config.CheckSettings(); err != nil {
		return err
	}

	// Setup the context used throughout the collection
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	ctx = context.WithValue(ctx, requests.ContextConfig, c.Config)
	ctx = context.WithValue(ctx, requests.ContextEventBus, c.Bus)
	c.ctx = ctx
	defer cancel()

	go func() {
		<-ctx.Done()
		close(c.Output)
	}()

	source := newIntelSource(c)
	sink := c.makeOutputSink()

	var stages []pipeline.Stage
	max := c.Config.MaxDNSQueries * int(resolvers.QueryTimeout.Seconds())
	stages = append(stages, pipeline.DynamicPool("", c.makeDNSTaskFunc(), max))
	if c.Config.Active {
		stages = append(stages, pipeline.FIFO("", newActiveTask(c, 100)))
	}
	stages = append(stages, pipeline.FIFO("filter", c.makeFilterTaskFunc()))

	for _, addr := range c.Config.Addresses {
		source.InputAddress(&requests.AddrRequest{Address: addr.String()})
	}

	for _, cidr := range append(c.Config.CIDRs, c.asnsToCIDRs()...) {
		// Skip IPv6 netblocks, since they are simply too large
		if ip := cidr.IP.Mask(cidr.Mask); amassnet.IsIPv6(ip) {
			continue
		}

		go func() {
			for _, addr := range amassnet.AllHosts(cidr) {
				source.InputAddress(&requests.AddrRequest{Address: addr.String()})
			}
		}()
	}

	return pipeline.NewPipeline(stages...).Execute(ctx, source, sink)
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

		msg := resolvers.ReverseMsg(req.Address)
		if msg == nil {
			return nil, nil
		}

		var nxdomain bool
		addrinfo := requests.AddressInfo{Address: ip}
		resp, err := c.Sys.Pool().Query(ctx, msg, resolvers.PriorityLow, func(times, priority int, m *dns.Msg) bool {
			// Try one more time if we receive NXDOMAIN
			if m.Rcode == dns.RcodeNameError && !nxdomain {
				nxdomain = true
				return true
			}
			return resolvers.PoolRetryPolicy(times, priority, m)
		})
		if err == nil {
			ans := resolvers.ExtractAnswers(resp)

			if len(ans) > 0 {
				d := strings.TrimSpace(resolvers.FirstProperSubdomain(c.ctx, c.Sys.Pool(), ans[0].Data, resolvers.PriorityHigh))

				if d != "" {
					go pipeline.SendData(ctx, "filter", &requests.Output{
						Name:      d,
						Domain:    d,
						Addresses: []requests.AddressInfo{addrinfo},
						Tag:       requests.DNS,
						Sources:   []string{"Reverse DNS"},
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

		if req, ok := data.(*requests.Output); ok && req != nil && !c.filter.Duplicate(req.Domain) {
			return data, nil
		}
		return nil, nil
	})
}

func (c *Collection) asnsToCIDRs() []*net.IPNet {
	var cidrs []*net.IPNet

	if len(c.Config.ASNs) == 0 {
		return cidrs
	}

	var setLock sync.Mutex
	cidrSet := stringset.New()
	fn := func(req *requests.ASNRequest) {
		setLock.Lock()
		cidrSet.Union(req.Netblocks)
		setLock.Unlock()
	}

	c.Bus.Subscribe(requests.NewASNTopic, fn)
	defer c.Bus.Unsubscribe(requests.NewASNTopic, fn)

	// Send the ASN requests to the data sources
	for _, src := range c.srcs {
		for _, asn := range c.Config.ASNs {
			src.Request(c.ctx, &requests.ASNRequest{ASN: asn})
		}
	}

	// Wait for the ASN requests to return responses
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case <-c.done:
			return cidrs
		case <-t.C:
			break loop
		}
	}

	for _, asn := range c.Config.ASNs {
		if req := c.Sys.Cache().ASNSearch(asn); req != nil {
			fn(req)
		}
	}

	filter := stringfilter.NewStringFilter()
	// Do not return CIDRs that are already in the config
	for _, cidr := range c.Config.CIDRs {
		filter.Duplicate(cidr.String())
	}

	for _, netblock := range cidrSet.Slice() {
		_, ipnet, err := net.ParseCIDR(netblock)

		if err == nil && !filter.Duplicate(ipnet.String()) {
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

	ch := make(chan time.Time, 10)
	filter := stringfilter.NewStringFilter()
	collect := func(req *requests.WhoisRequest) {
		ch <- time.Now()

		for _, d := range req.NewDomains {
			if !filter.Duplicate(d) {
				c.Output <- &requests.Output{
					Name:    d,
					Domain:  d,
					Tag:     req.Tag,
					Sources: []string{req.Source},
				}
			}
		}
	}
	c.Bus.Subscribe(requests.NewWhoisTopic, collect)
	defer c.Bus.Unsubscribe(requests.NewWhoisTopic, collect)

	// Setup the context used throughout the collection
	ctx := context.WithValue(context.Background(), requests.ContextConfig, c.Config)
	c.ctx = context.WithValue(ctx, requests.ContextEventBus, c.Bus)

	// Send the whois requests to the data sources
	for _, src := range c.srcs {
		for _, domain := range c.Config.Domains() {
			src.Request(c.ctx, &requests.WhoisRequest{Domain: domain})
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
		case l := <-ch:
			if l.After(last) {
				last = l
			}
		case now := <-t.C:
			if now.Sub(last) > 10*time.Second {
				break loop
			}
		}
	}

	close(c.Output)
	return nil
}
