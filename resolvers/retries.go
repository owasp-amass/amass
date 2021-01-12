// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"github.com/miekg/dns"
)

// ResolverErrRcode is our made up rcode to indicate an interface error.
const ResolverErrRcode = 100

// TimeoutRcode is our made up rcode to indicate that a query timed out.
const TimeoutRcode = 101

// Retry is the definition for the callbacks used in the Resolver interface.
type Retry func(times int, priority int, msg *dns.Msg) bool

// RetryCodes are the rcodes that cause the resolver to suggest trying again.
var RetryCodes = []int{
	TimeoutRcode,
	ResolverErrRcode,
}

// PoolRetryCodes are the rcodes that cause the pool to suggest trying again.
var PoolRetryCodes = []int{
	TimeoutRcode,
	ResolverErrRcode,
	dns.RcodeRefused,
	dns.RcodeServerFailure,
	dns.RcodeNotImplemented,
}

// RetryPolicy is the default policy used throughout Amass
// to determine if a DNS query should be performed again.
func RetryPolicy(times, priority int, msg *dns.Msg) bool {
	if attemptsExceeded(times, priority) {
		return false
	}
	if msg == nil {
		return false
	}

	for _, code := range RetryCodes {
		if msg.Rcode == code {
			return true
		}
	}
	return false
}

// PoolRetryPolicy is the default policy used by the resolver pool
// to determine if a DNS query should be performed again.
func PoolRetryPolicy(times, priority int, msg *dns.Msg) bool {
	if attemptsExceeded(times, priority) {
		return false
	}
	if msg == nil {
		return false
	}

	for _, code := range PoolRetryCodes {
		if msg.Rcode == code {
			return true
		}
	}
	return false
}

func attemptsExceeded(times, priority int) bool {
	var attempts int

	switch priority {
	case PriorityCritical:
		attempts = 500
	case PriorityHigh:
		attempts = 250
	case PriorityNormal:
		attempts = 100
	case PriorityLow:
		attempts = 50
	}

	return times > attempts
}
