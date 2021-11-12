// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"strings"

	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	"github.com/caffix/resolve"
	"github.com/caffix/stringset"
)

// subdomainTask handles newly discovered proper subdomain names in the enumeration.
type subdomainTask struct {
	enum            *Enumeration
	queue           queue.Queue
	cnames          *stringset.Set
	withinWildcards *stringset.Set
	timesChan       chan *timesReq
	done            chan struct{}
}

// newSubdomainTask returns an initialized SubdomainTask.
func newSubdomainTask(e *Enumeration) *subdomainTask {
	r := &subdomainTask{
		enum:            e,
		queue:           queue.NewQueue(),
		cnames:          stringset.New(),
		withinWildcards: stringset.New(),
		timesChan:       make(chan *timesReq, 10),
		done:            make(chan struct{}, 2),
	}

	go r.timesManager()
	return r
}

// Stop releases resources allocated by the instance.
func (r *subdomainTask) Stop() {
	close(r.done)
	r.queue.Process(func(e interface{}) {})
	r.cnames.Close()
	r.withinWildcards.Close()
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

	if r.checkForSubdomains(ctx, req, tp) {
		r.queue.Append(&requests.ResolvedRequest{
			Name:    req.Name,
			Domain:  req.Domain,
			Records: req.Records,
			Tag:     req.Tag,
			Source:  req.Source,
		})
	}
	return req, nil
}

func (r *subdomainTask) checkForSubdomains(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) bool {
	nlabels := strings.Split(req.Name, ".")
	// Is this large enough to consider further?
	if len(nlabels) < 2 {
		return false
	}

	dlabels := strings.Split(req.Domain, ".")
	// It cannot have fewer labels than the root domain name
	if len(nlabels)-1 < len(dlabels) {
		return false
	}

	sub := strings.TrimSpace(strings.Join(nlabels[1:], "."))
	times := r.timesForSubdomain(sub)
	if times == 1 && r.subWithinWildcard(ctx, sub, req.Domain) {
		r.withinWildcards.Insert(sub)
		return false
	} else if times > 1 && r.withinWildcards.Has(sub) {
		return false
	} else if times == 1 && r.enum.Graph.IsCNAMENode(ctx, sub) {
		r.cnames.Insert(sub)
		return false
	} else if times > 1 && r.cnames.Has(sub) {
		return false
	} else if times > r.enum.Config.MinForRecursive {
		return true
	}

	subreq := &requests.SubdomainRequest{
		Name:   sub,
		Domain: req.Domain,
		Tag:    req.Tag,
		Source: req.Source,
		Times:  times,
	}

	r.queue.Append(subreq)
	if times == 1 {
		pipeline.SendData(ctx, "root", subreq, tp)
	}
	return true
}

func (r *subdomainTask) subWithinWildcard(ctx context.Context, name, domain string) bool {
	for _, t := range InitialQueryTypes {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		msg := resolve.QueryMsg("a."+name, t)
		resp, err := r.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityHigh, resolve.PoolRetryPolicy)
		if err == nil && resp != nil && len(resp.Answer) > 0 &&
			r.enum.Sys.Pool().WildcardType(ctx, resp, domain) != resolve.WildcardTypeNone {
			return true
		}
	}
	return false
}

// OutputRequests sends discovered subdomain names to the enumeration data sources.
func (r *subdomainTask) OutputRequests(num int) int {
	var count int

	if num <= 0 {
		return count
	}
loop:
	for ; count < num; count++ {
		select {
		case <-r.done:
			break loop
		default:
		}

		element, ok := r.queue.Next()
		if !ok {
			break loop
		}

		for _, src := range r.enum.srcs {
			switch v := element.(type) {
			case *requests.ResolvedRequest:
				src.Request(r.enum.ctx, v)
				if r.enum.Config.Alterations && src.String() == "Alterations" {
					count += len(r.enum.Config.AltWordlist)
				}
				if r.enum.Config.BruteForcing && src.String() == "Brute Forcing" && r.enum.Config.MinForRecursive == 0 {
					count += len(r.enum.Config.Wordlist)
				}
			case *requests.SubdomainRequest:
				src.Request(r.enum.ctx, v)
				if r.enum.Config.BruteForcing && src.String() == "Brute Forcing" && v.Times >= r.enum.Config.MinForRecursive {
					count += len(r.enum.Config.Wordlist)
				}
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
