// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"strings"

	"github.com/miekg/dns"
)

// FirstProperSubdomain returns the first subdomain name using the provided name and
// Resolver that responds successfully to a DNS query for the NS record type.
func FirstProperSubdomain(ctx context.Context, r Resolver, name string, priority int) string {
	var domain string

	// Obtain all parts of the subdomain name
	labels := strings.Split(strings.TrimSpace(name), ".")

	for i := 0; i < len(labels)-1; i++ {
		sub := strings.Join(labels[i:], ".")

		msg := QueryMsg(sub, dns.TypeNS)
		if ns, err := r.Query(ctx, msg, priority, RetryPolicy); err == nil {
			rr := ExtractAnswers(ns)
			if len(rr) == 0 {
				continue
			}

			d := AnswersByType(rr, dns.TypeNS)
			if len(d) == 0 {
				continue
			}

			pieces := strings.Split(d[0].Data, ",")
			domain = pieces[0]
			break
		}
	}

	return domain
}
