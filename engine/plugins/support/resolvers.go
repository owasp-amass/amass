// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/conn"
	"github.com/owasp-amass/resolve/pool"
	"github.com/owasp-amass/resolve/selectors"
	"github.com/owasp-amass/resolve/servers"
	"github.com/owasp-amass/resolve/utils"
	"github.com/owasp-amass/resolve/wildcards"
	"golang.org/x/net/publicsuffix"
)

var trusted *pool.Pool
var detector *wildcards.Detector

func PerformQuery(name string, qtype uint16) ([]dns.RR, error) {
	for num := 0; num < 10; num++ {
		msg := utils.QueryMsg(name, qtype)
		if qtype == dns.TypePTR {
			msg = utils.ReverseMsg(name)
		}

		if resp, err := dnsQuery(msg, trusted); err == nil && resp != nil {
			if wildcardDetected(resp, detector) {
				return nil, errors.New("wildcard detected")
			}
			if len(resp.Answer) > 0 {
				if rr := utils.AnswersByType(resp, qtype); len(rr) > 0 {
					return rr, nil
				}
			}
		}
	}
	return nil, errors.New("no valid answers")
}

func wildcardDetected(resp *dns.Msg, r *wildcards.Detector) bool {
	name := strings.ToLower(utils.RemoveLastDot(resp.Question[0].Name))

	if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil && dom != "" {
		return r.WildcardDetected(context.TODO(), resp, dom)
	}
	return false
}

func dnsQuery(msg *dns.Msg, r *pool.Pool) (*dns.Msg, error) {
	if resp, err := r.Exchange(context.TODO(), msg); err != nil {
		return nil, err
	} else if resp.Rcode == dns.RcodeNameError {
		return nil, errors.New("name does not exist")
	} else if resp.Rcode == dns.RcodeSuccess {
		if len(resp.Answer) == 0 {
			return nil, errors.New("no record of this type")
		}
		return resp, nil
	}
	return nil, errors.New("unexpected response")
}

func trustedResolvers() *pool.Pool {
	timeout := 2 * time.Second
	cpus := runtime.NumCPU()
	// wildcard detector
	serv := servers.NewNameserver("8.8.8.8")
	wconns := conn.New(cpus, selectors.NewSingle(timeout, serv))
	detector = wildcards.NewDetector(serv, wconns, nil)
	// the server pool
	sel := selectors.NewAuthoritative(timeout, servers.NewNameserver)
	conns := conn.New(cpus, sel)
	return pool.New(0, sel, conns, nil)
}
