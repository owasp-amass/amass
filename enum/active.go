// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/eventbus"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	"github.com/caffix/resolve"
	"github.com/miekg/dns"
)

// activeTask is the task that handles all requests related to active enumeration within the pipeline.
type activeTask struct {
	enum      *Enumeration
	queue     queue.Queue
	tokenPool chan struct{}
}

type taskArgs struct {
	Ctx    context.Context
	Data   pipeline.Data
	Params pipeline.TaskParams
}

// newActiveTask returns a activeTask specific to the provided Enumeration.
func newActiveTask(e *Enumeration, max int) *activeTask {
	if max <= 0 {
		return nil
	}

	tokenPool := make(chan struct{}, max)
	for i := 0; i < max; i++ {
		tokenPool <- struct{}{}
	}

	a := &activeTask{
		enum:      e,
		queue:     queue.NewQueue(),
		tokenPool: tokenPool,
	}

	go a.processQueue()
	return a
}

func (a *activeTask) Stop() {
	a.queue.Process(func(e interface{}) {})
}

// Process implements the pipeline Task interface.
func (a *activeTask) Process(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
	select {
	case <-ctx.Done():
		return nil, nil
	default:
	}

	var ok bool
	switch data.(type) {
	case *requests.DNSRequest:
		ok = true
	case *requests.ZoneXFRRequest:
		ok = true
	}

	if ok {
		a.queue.Append(&taskArgs{
			Ctx:    ctx,
			Data:   data.Clone(),
			Params: tp,
		})
	}

	return data, nil
}

func (a *activeTask) processQueue() {
	for {
		select {
		case <-a.enum.done:
			return
		case <-a.queue.Signal():
			a.processTask()
		}
	}
}

func (a *activeTask) processTask() {
	select {
	case <-a.enum.ctx.Done():
		return
	case <-a.enum.done:
		return
	case <-a.tokenPool:
		element, ok := a.queue.Next()
		if !ok {
			a.tokenPool <- struct{}{}
			return
		}

		args := element.(*taskArgs)
		switch v := args.Data.(type) {
		case *requests.DNSRequest:
			go a.crawlName(args.Ctx, v, args.Params)
		case *requests.ZoneXFRRequest:
			go a.zoneTransfer(args.Ctx, v, args.Params)
			go a.zoneWalk(args.Ctx, v, args.Params)
		}
	}
}

func (a *activeTask) crawlName(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) {
	defer func() { a.tokenPool <- struct{}{} }()

	if req == nil || !req.Valid() {
		return
	}

	cfg := a.enum.Config
	var protocol string
	for _, port := range cfg.Ports {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if strings.HasSuffix(strconv.Itoa(port), "80") {
			protocol = "http://"
		} else {
			protocol = "https://"
		}
		u := protocol + req.Name + ":" + strconv.Itoa(port)
		names, err := http.Crawl(ctx, u, cfg.Domains(), 50, a.enum.crawlFilter)
		if err != nil {
			if cfg.Verbose {
				cfg.Log.Printf("Active Crawl: %v", err)
			}
			continue
		}

		for _, name := range names {
			if n := strings.TrimSpace(name); n != "" {
				if domain := cfg.WhichDomain(n); domain != "" {
					pipeline.SendData(ctx, "new", &requests.DNSRequest{
						Name:   n,
						Domain: domain,
						Tag:    requests.CRAWL,
						Source: "Active Crawl",
					}, tp)
				}
			}
		}
	}
}

func (a *activeTask) zoneTransfer(ctx context.Context, req *requests.ZoneXFRRequest, tp pipeline.TaskParams) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	addr, err := a.nameserverAddr(ctx, req.Server)
	if addr == "" {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("DNS: Zone XFR failed: %v", err))
		return
	}

	reqs, err := ZoneTransfer(req.Name, req.Domain, addr)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("DNS: Zone XFR failed: %s: %v", req.Server, err))
		return
	}

	for _, req := range reqs {
		// Zone Transfers can reveal DNS wildcards
		if name := amassdns.RemoveAsteriskLabel(req.Name); len(name) < len(req.Name) {
			// Signal the wildcard discovery
			pipeline.SendData(ctx, "dns", &requests.DNSRequest{
				Name:   "www." + name,
				Domain: req.Domain,
				Tag:    requests.DNS,
				Source: "DNS",
			}, tp)
			continue
		}

		pipeline.SendData(ctx, "filter", req, tp)
	}
}

func (a *activeTask) zoneWalk(ctx context.Context, req *requests.ZoneXFRRequest, tp pipeline.TaskParams) {
	defer func() { a.tokenPool <- struct{}{} }()

	cfg, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	addr, err := a.nameserverAddr(ctx, req.Server)
	if addr == "" {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("DNS: Zone Walk failed: %v", err))
		return
	}

	r := resolve.NewBaseResolver(addr, 50, a.enum.Config.Log)
	if r == nil {
		return
	}
	defer r.Stop()

	names, _, err := resolve.NsecTraversal(ctx, r, req.Name, resolve.PriorityHigh)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("DNS: Zone Walk failed: %s: %v", req.Name, err))
		return
	}

	for _, nsec := range names {
		name := resolve.RemoveLastDot(nsec.NextDomain)

		if domain := cfg.WhichDomain(name); domain != "" {
			pipeline.SendData(ctx, "new", &requests.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    requests.DNS,
				Source: "NSEC Walk",
			}, tp)
		}
	}
}

func (a *activeTask) nameserverAddr(ctx context.Context, server string) (string, error) {
	var err error
	var found bool
	var qtype uint16
	var resp *dns.Msg

	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg := resolve.QueryMsg(server, t)

		resp, err = a.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityHigh, resolve.RetryPolicy)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			qtype = t
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("DNS server %s has no A or AAAA records", server)
	}

	rr := resolve.AnswersByType(resolve.ExtractAnswers(resp), qtype)
	if len(rr) == 0 {
		return "", fmt.Errorf("DNS server %s has no A or AAAA records", server)
	}

	return rr[0].Data, nil
}
