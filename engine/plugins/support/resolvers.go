// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/miekg/dns"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	"github.com/owasp-amass/resolve/utils"
	"golang.org/x/net/publicsuffix"
)

var (
	ErrNameDoesNotExist     = errors.New("name does not exist")
	ErrNoRecordOfThisType   = errors.New("no record of this type")
	ErrFailedMaxDNSAttempts = errors.New("failed the maximum number of DNS attempts")
)

// PerformQuery asks the session's resolvers for name's records of qtype,
// retrying up to ten times. The resolvers are the pool ctx carries
// (amassdns.WithResolvers), or the engine's default pool. Each query is
// counted for the session whose context ctx is (et.NetUsage), so the
// sessions' shares of the resolvers can be compared.
func PerformQuery(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	return performQuery(ctx, name, qtype, true)
}

// PerformQueryNoWildcard is PerformQuery without wildcard suppression, for a
// name obtained from an authoritative DNS record (a CNAME target). Wildcard
// suppression exists to discard brute-forced or altered names that resolve only
// because their zone serves a wildcard; a name DNS handed us in a record is
// real, so its records are returned even when the zone wildcards.
func PerformQueryNoWildcard(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	return performQuery(ctx, name, qtype, false)
}

func performQuery(ctx context.Context, name string, qtype uint16, checkWildcard bool) ([]dns.RR, error) {
	resolvers := amassdns.ResolversFrom(ctx)
	if resolvers == nil {
		return nil, errors.New("no DNS resolvers are available")
	}

	usage := et.NetUsageFrom(ctx)
	for i := 1; i <= 10; i++ {
		msg := utils.QueryMsg(name, qtype)
		if qtype == dns.TypePTR {
			msg = utils.ReverseMsg(name)
		}

		start := time.Now()
		resp, err := dnsQuery(ctx, msg, resolvers)
		switch {
		case err == nil && resp != nil:
			usage.DNSQuery(et.DNSAnswered, time.Since(start))
		case err == ErrNameDoesNotExist || err == ErrNoRecordOfThisType:
			usage.DNSQuery(et.DNSNoRecord, time.Since(start))
		default:
			usage.DNSQuery(et.DNSFailed, time.Since(start))
		}

		if err == nil && resp != nil {
			if checkWildcard && wildcardDetected(ctx, resp, resolvers) {
				return nil, errors.New("wildcard detected")
			}
			if len(resp.Answer) > 0 {
				if rr := utils.AnswersByType(resp, qtype); len(rr) > 0 {
					return rr, nil
				}
			}
		} else if err == ErrNameDoesNotExist || err == ErrNoRecordOfThisType {
			return nil, err
		}
	}
	return nil, ErrFailedMaxDNSAttempts
}

func wildcardDetected(ctx context.Context, resp *dns.Msg, r *amassdns.Resolvers) bool {
	name := strings.ToLower(utils.RemoveLastDot(resp.Question[0].Name))

	if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil && dom != "" {
		return r.WildcardDetected(ctx, resp, dom)
	}
	return false
}

func dnsQuery(ctx context.Context, msg *dns.Msg, r *amassdns.Resolvers) (*dns.Msg, error) {
	if resp, err := r.Exchange(ctx, msg); err != nil {
		return nil, err
	} else if resp.Rcode == dns.RcodeNameError {
		return nil, ErrNameDoesNotExist
	} else if resp.Rcode == dns.RcodeSuccess {
		if len(resp.Answer) == 0 {
			return nil, ErrNoRecordOfThisType
		}
		return resp, nil
	}
	return nil, errors.New("unexpected response")
}
