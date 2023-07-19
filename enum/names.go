// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"context"
	"strings"

	"github.com/caffix/pipeline"
	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v4/requests"
)

// subdomainTask handles newly discovered proper subdomain names in the enumeration.
type subdomainTask struct {
	enum            *Enumeration
	cnames          *stringset.Set
	withinWildcards *stringset.Set
	timesChan       chan *timesReq
	done            chan struct{}
}

// newSubdomainTask returns an initialized SubdomainTask.
func newSubdomainTask(e *Enumeration) *subdomainTask {
	r := &subdomainTask{
		enum:            e,
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
		r.enum.sendRequests(&requests.ResolvedRequest{
			Name:    req.Name,
			Domain:  req.Domain,
			Records: req.Records,
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
		return true
	}

	sub := strings.TrimSpace(strings.Join(nlabels[1:], "."))
	times := r.timesForSubdomain(sub)
	if times == 1 && r.subWithinWildcard(ctx, sub, req.Domain) {
		r.withinWildcards.Insert(sub)
		return false
	} else if times > 1 && r.withinWildcards.Has(sub) {
		return false
	} else if times == 1 && r.enum.graph.IsCNAMENode(ctx, sub, r.enum.Config.CollectionStartTime) {
		r.cnames.Insert(sub)
		return true
	} else if times > 1 && r.cnames.Has(sub) {
		return true
	}

	subreq := &requests.SubdomainRequest{
		Name:   sub,
		Domain: req.Domain,
		Times:  times,
	}

	r.enum.sendRequests(subreq)
	if times == 1 {
		pipeline.SendData(ctx, "root", subreq, tp)
	}
	return true
}

func (r *subdomainTask) subWithinWildcard(ctx context.Context, name, domain string) bool {
	for _, t := range FwdQueryTypes {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		if resp, err := r.enum.fwdQuery(ctx, "a."+name, t); err == nil &&
			len(resp.Answer) > 0 && r.enum.Sys.TrustedResolvers().WildcardDetected(ctx, resp, domain) {
			return true
		}
	}
	return false
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
