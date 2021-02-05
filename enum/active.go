// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/OWASP/Amass/v3/datasrcs"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/caffix/eventbus"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
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
	case *requests.AddrRequest:
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
		case *requests.AddrRequest:
			if v.InScope {
				go a.certEnumeration(args.Ctx, v, args.Params)
			}
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

	// Hold the pipeline during slow activities
	tp.NewData() <- req
	defer func() { tp.ProcessedData() <- req }()

	cfg := a.enum.Config
	var protocol string
	for _, port := range cfg.Ports {
		if strings.HasSuffix(strconv.Itoa(port), "443") {
			protocol = "https://"
		} else {
			// Sending HTTP request to HTTPS port will redirect you to the correct protocol sometimes
			protocol = "http://"
		}
		u := protocol + req.Domain + ":" + port

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
					go pipeline.SendData(ctx, "new", &requests.DNSRequest{
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

func (a *activeTask) certEnumeration(ctx context.Context, req *requests.AddrRequest, tp pipeline.TaskParams) {
	defer func() { a.tokenPool <- struct{}{} }()

	if req == nil || !req.Valid() {
		return
	}

	// Hold the pipeline during slow activities
	tp.NewData() <- req
	defer func() { tp.ProcessedData() <- req }()

	for _, name := range http.PullCertificateNames(ctx, req.Address, a.enum.Config.Ports) {
		if n := strings.TrimSpace(name); n != "" {
			if domain := a.enum.Config.WhichDomain(n); domain != "" {
				go pipeline.SendData(ctx, "new", &requests.DNSRequest{
					Name:   n,
					Domain: domain,
					Tag:    requests.CERT,
					Source: "Active Cert",
				}, tp)
			}
		}
	}
}

func (a *activeTask) zoneTransfer(ctx context.Context, req *requests.ZoneXFRRequest, tp pipeline.TaskParams) {
	_, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	// Hold the pipeline during slow activities
	tp.NewData() <- req
	defer func() { tp.ProcessedData() <- req }()

	addr, err := a.nameserverAddr(ctx, req.Server)
	if addr == "" {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("DNS: Zone XFR failed: %v", err))
		return
	}

	reqs, err := resolvers.ZoneTransfer(req.Name, req.Domain, addr)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("DNS: Zone XFR failed: %s: %v", req.Server, err))
		return
	}

	for _, req := range reqs {
		go pipeline.SendData(ctx, "filter", req, tp)
	}
}

func (a *activeTask) zoneWalk(ctx context.Context, req *requests.ZoneXFRRequest, tp pipeline.TaskParams) {
	defer func() { a.tokenPool <- struct{}{} }()

	cfg, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	// Hold the pipeline during slow activities
	tp.NewData() <- req
	defer func() { tp.ProcessedData() <- req }()

	addr, err := a.nameserverAddr(ctx, req.Server)
	if addr == "" {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("DNS: Zone Walk failed: %v", err))
		return
	}

	r := resolvers.NewBaseResolver(addr, 10, a.enum.Config.Log)
	if r == nil {
		return
	}
	defer r.Stop()

	names, _, err := resolvers.NsecTraversal(ctx, r, req.Name, resolvers.PriorityHigh)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("DNS: Zone Walk failed: %s: %v", req.Name, err))
		return
	}

	for _, name := range names {
		if domain := cfg.WhichDomain(name); domain != "" {
			go pipeline.SendData(ctx, "new", &requests.DNSRequest{
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
		msg := resolvers.QueryMsg(server, t)

		resp, err = a.enum.Sys.Pool().Query(ctx, msg, resolvers.PriorityHigh, resolvers.RetryPolicy)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			qtype = t
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("DNS server %s has no A or AAAA records", server)
	}

	ans := resolvers.ExtractAnswers(resp)
	rr := resolvers.AnswersByType(ans, qtype)
	if len(rr) == 0 {
		return "", fmt.Errorf("DNS server %s has no A or AAAA records", server)
	}

	return rr[0].Data, nil
}
