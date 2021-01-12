// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
)

// The priority levels for Resolver DNS queries.
const (
	PriorityLow int = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical
)

// Resolver performs DNS resolutions.
type Resolver interface {
	fmt.Stringer

	// Stop will stop the Resolver.
	Stop() error

	// Stopped returns true if the Resolver is already stopped.
	Stopped() bool

	// Query performs a DNS query for the provided name and message type.
	Query(ctx context.Context, msg *dns.Msg, priority int, retry Retry) (*dns.Msg, error)

	// WildcardType returns the DNS wildcard type for the FQDN in the provided message.
	WildcardType(ctx context.Context, msg *dns.Msg, domain string) int
}
