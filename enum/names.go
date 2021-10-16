// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"strings"

	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
)

// subdomainTask handles newly discovered proper subdomain names in the enumeration.
type subdomainTask struct {
	enum      *Enumeration
	queue     queue.Queue
	timesChan chan *timesReq
	done      chan struct{}
}

// newSubdomainTask returns an initialized SubdomainTask.
func newSubdomainTask(e *Enumeration) *subdomainTask {
	r := &subdomainTask{
		enum:      e,
		queue:     queue.NewQueue(),
		timesChan: make(chan *timesReq, 10),
		done:      make(chan struct{}, 2),
	}

	go r.timesManager()
	return r
}

// Stop releases resources allocated by the instance.
func (r *subdomainTask) Stop() {
	close(r.done)
	r.queue.Process(func(e interface{}) {})
}

// Process implements the pipeline Task interface.
func (r *subdomainTask) Process(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
	select {
	case <-ctx.Done():
		return nil, nil
	default:
	}

	req, ok := data.(*requests.DNSRequest)
	if !ok {
		return data, nil
	}
	if req == nil || !r.enum.Config.IsDomainInScope(req.Name) {
		return nil, nil
	}
	// Do not further evaluate service subdomains
	for _, label := range strings.Split(req.Name, ".") {
		l := strings.ToLower(label)

		if l == "_tcp" || l == "_udp" || l == "_tls" {
			return nil, nil
		}
	}

	r.queue.Append(&requests.ResolvedRequest{
		Name:    req.Name,
		Domain:  req.Domain,
		Records: append([]requests.DNSAnswer(nil), req.Records...),
		Tag:     req.Tag,
		Source:  req.Source,
	})
	return r.checkForSubdomains(ctx, req, tp)
}

func (r *subdomainTask) checkForSubdomains(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) (pipeline.Data, error) {
	labels := strings.Split(req.Name, ".")
	num := len(labels)
	// Is this large enough to consider further?
	if num < 2 {
		return req, nil
	}
	// It cannot have fewer labels than the root domain name
	if num-1 < len(strings.Split(req.Domain, ".")) {
		return req, nil
	}

	sub := strings.TrimSpace(strings.Join(labels[1:], "."))
	times := r.timesForSubdomain(sub)
	if times > r.enum.Config.MinForRecursive || r.enum.Graph.IsCNAMENode(ctx, sub) {
		return req, nil
	}

	subreq := &requests.SubdomainRequest{
		Name:    sub,
		Domain:  req.Domain,
		Records: append([]requests.DNSAnswer(nil), req.Records...),
		Tag:     req.Tag,
		Source:  req.Source,
		Times:   times,
	}

	r.queue.Append(subreq)
	if times == 1 {
		pipeline.SendData(ctx, "root", subreq, tp)
	}
	return req, nil
}

// OutputRequests sends discovered subdomain names to the enumeration data sources.
func (r *subdomainTask) OutputRequests(num int) int {
	var count int
loop:
	for ; count < num; count++ {
		select {
		case <-r.done:
			break loop
		default:
		}

		element, ok := r.queue.Next()
		if !ok {
			break
		}

		for _, src := range r.enum.srcs {
			switch v := element.(type) {
			case *requests.ResolvedRequest:
				src.Request(r.enum.ctx, v.Clone())
			case *requests.SubdomainRequest:
				src.Request(r.enum.ctx, v.Clone())
			}
		}
	}
	return count
}

func (r *subdomainTask) timesForSubdomain(sub string) int {
	ch := make(chan int, 2)

	r.timesChan <- &timesReq{
		Sub: sub,
		Ch:  ch,
	}
	return <-ch
}

type timesReq struct {
	Sub string
	Ch  chan int
}

func (r *subdomainTask) timesManager() {
	subdomains := make(map[string]int)

	for {
		select {
		case <-r.done:
			return
		case req := <-r.timesChan:
			times, found := subdomains[req.Sub]
			if found {
				times++
			} else {
				times = 1
			}

			subdomains[req.Sub] = times
			req.Ch <- times
		}
	}
}
