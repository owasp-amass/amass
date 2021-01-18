// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"fmt"
	"strings"

	"github.com/OWASP/Amass/v3/datasrcs"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/caffix/eventbus"
	"github.com/caffix/pipeline"
	"github.com/miekg/dns"
)

// activeTask is the task that handles all requests related to active enumeration within the pipeline.
type activeTask struct {
	enum *Enumeration
}

// newActiveTask returns a activeTask specific to the provided Enumeration.
func newActiveTask(e *Enumeration) *activeTask {
	return &activeTask{enum: e}
}

// Process implements the pipeline Task interface.
func (a *activeTask) Process(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
	select {
	case <-ctx.Done():
		return nil, nil
	default:
	}

	switch v := data.(type) {
	case *requests.AddrRequest:
		go a.certEnumeration(ctx, v, tp)
	case *requests.ZoneXFRRequest:
		go a.zoneTransfer(ctx, v, tp)
		go a.zoneWalk(ctx, v, tp)
	}

	return data, nil
}

func (a *activeTask) certEnumeration(ctx context.Context, req *requests.AddrRequest, tp pipeline.TaskParams) {
	if req == nil || !req.Valid() {
		return
	}

	// Hold the pipeline during slow activities
	tp.NewData() <- req
	defer func() { tp.ProcessedData() <- req }()

	for _, name := range http.PullCertificateNames(req.Address, a.enum.Config.Ports) {
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
