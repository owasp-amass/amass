// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"errors"
	"log/slog"
	"sync"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

// zoneFailLimit is how many probes below one apex may fail outright (no
// answer after every attempt) before the rest of that apex's probes are
// skipped for the session. A zone whose servers do not answer the probes,
// such as a large provider's mail zone reached through a target's MX, would
// otherwise cost every one of them the resolver's full retries. A name that
// does not exist is an answer and does not count.
const zoneFailLimit = 3

// probeWorkers bounds the probes below one apex that run at once, so a zone
// that stops answering is noticed before every probe has been sent.
const probeWorkers = 8

// errZoneUnresponsive is returned for a probe skipped because its zone
// stopped answering.
var errZoneUnresponsive = errors.New("the zone stopped answering probes")

// probe asks for qtype at name, a name below zone, unless zoneFailLimit
// probes below zone have already failed outright in this session.
func (d *dnsSubs) probe(e *et.Event, zone, name string, qtype uint16) ([]dns.RR, error) {
	if d.zoneFailures(e, zone) >= zoneFailLimit {
		return nil, errZoneUnresponsive
	}

	rr, err := support.PerformQuery(e.Session.Ctx(), name, qtype)
	if errors.Is(err, support.ErrFailedMaxDNSAttempts) {
		e.Session.Log().Warn(err.Error(), "fqdn", name,
			slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		if d.zoneFailed(e, zone) == zoneFailLimit {
			e.Session.Log().Info("zone stopped answering probes; skipping the rest of its probes", "zone", zone,
				slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		}
	}
	return rr, err
}

// probeAll asks for qtype at each of names, all below zone, at most
// probeWorkers at a time, and returns each name's answer in the order of
// names (nil when it gave none).
func (d *dnsSubs) probeAll(e *et.Event, zone string, names []string, qtype uint16) [][]dns.RR {
	out := make([][]dns.RR, len(names))
	sem := make(chan struct{}, probeWorkers)

	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, name string) {
			defer wg.Done()
			defer func() { <-sem }()

			if rr, err := d.probe(e, zone, name, qtype); err == nil {
				out[i] = rr
			}
		}(i, name)
	}

	wg.Wait()
	return out
}

// zoneFailures returns how many probes below zone failed outright in the
// event's session.
func (d *dnsSubs) zoneFailures(e *et.Event, zone string) int {
	d.Lock()
	defer d.Unlock()

	return d.sessionState(e).failures[zone]
}

// zoneFailed counts a probe below zone that failed outright and returns the
// new count.
func (d *dnsSubs) zoneFailed(e *et.Event, zone string) int {
	d.Lock()
	defer d.Unlock()

	s := d.sessionState(e)
	s.failures[zone]++
	return s.failures[zone]
}
