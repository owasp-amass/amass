// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/OWASP/Amass/v3/services"
	"github.com/OWASP/Amass/v3/stringset"
)

// Enumeration is the object type used to execute a DNS enumeration with Amass.
type Enumeration struct {
	// Information sent in the context
	Config *config.Config
	Bus    *eventbus.EventBus
	Sys    services.System

	ctx context.Context

	coreSrvs []services.Service
	dataMgr  services.Service

	srcsLock sync.Mutex
	srcs     stringset.Set

	// The channel and queue that will receive the results
	Output       chan *requests.Output
	outputQueue  *queue.Queue
	outputFilter *stringset.StringFilter

	// Queue for the log messages
	logQueue *queue.Queue

	// Broadcast channel that indicates no further writes to the output channel
	done   chan struct{}
	closed sync.Once

	// Cache for the infrastructure data collected from online sources
	netCache *net.ASNCache

	nameMgr   *NameManager
	subMgr    *SubdomainManager
	bruteMgr  *BruteManager
	altMgr    *AlterationsManager
	guessMgr  *GuessManager
	domainMgr *DomainManager

	lastLock sync.Mutex
	last     time.Time

	perSecLock  sync.Mutex
	perSec      int64
	retries     int64
	numSeqZeros int64
	perSecFirst time.Time
	perSecLast  time.Time
}

// NewEnumeration returns an initialized Enumeration that has not been started yet.
func NewEnumeration(sys services.System) *Enumeration {
	e := &Enumeration{
		Config:       config.NewConfig(),
		Bus:          eventbus.NewEventBus(10000),
		Sys:          sys,
		coreSrvs:     sys.CoreServices(),
		srcs:         stringset.New(),
		Output:       make(chan *requests.Output, 1000),
		outputQueue:  new(queue.Queue),
		outputFilter: stringset.NewStringFilter(),
		logQueue:     new(queue.Queue),
		done:         make(chan struct{}),
		netCache:     net.NewASNCache(),
		last:         time.Now(),
		perSecFirst:  time.Now(),
		perSecLast:   time.Now(),
	}

	if ref := e.refToDataManager(); ref != nil {
		e.dataMgr = ref
		return e
	}
	return nil
}

func (e *Enumeration) refToDataManager() services.Service {
	for _, srv := range e.Sys.CoreServices() {
		if srv.String() == "Data Manager" {
			return srv
		}
	}
	return nil
}

// Done safely closes the done broadcast channel.
func (e *Enumeration) Done() {
	e.closed.Do(func() {
		close(e.done)
	})
}

// Start begins the DNS enumeration process for the Amass Enumeration object.
func (e *Enumeration) Start() error {
	if e.Output == nil {
		return errors.New("The enumeration did not have an output channel")
	} else if err := e.Config.CheckSettings(); err != nil {
		return err
	}

	// Setup the stringset of included data sources
	e.srcsLock.Lock()
	srcs := stringset.New()
	e.srcs.Intersect(srcs)
	srcs.InsertMany(e.Config.SourceFilter.Sources...)
	for _, src := range e.Sys.DataSources() {
		e.srcs.Insert(src.String())
	}
	if srcs.Len() > 0 && e.Config.SourceFilter.Include {
		e.srcs.Intersect(srcs)
	} else {
		e.srcs.Subtract(srcs)
	}
	e.srcsLock.Unlock()

	// Setup the context used throughout the enumeration
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, requests.ContextConfig, e.Config)
	e.ctx = context.WithValue(ctx, requests.ContextEventBus, e.Bus)

	if e.Config.Timeout > 0 {
		time.AfterFunc(time.Duration(e.Config.Timeout)*time.Minute, func() {
			e.Config.Log.Printf("Enumeration exceeded provided timeout")
			e.Done()
		})
	}

	e.srcsLock.Lock()
	for _, src := range e.Sys.DataSources() {
		if !e.srcs.Has(src.String()) {
			continue
		}

		// Put in requests for all the ASNs specified in the configuration
		for _, asn := range e.Config.ASNs {
			src.ASNRequest(e.ctx, &requests.ASNRequest{ASN: asn})
		}
	}
	e.srcsLock.Unlock()

	var managers []FQDNManager
	// Setup the various FQDNManager objects for the enumeration
	e.nameMgr = NewNameManager(e)
	defer e.nameMgr.Stop()
	managers = append(managers, e.nameMgr)
	e.Bus.Subscribe(requests.NewNameTopic, e.nameMgr.InputName)
	defer e.Bus.Unsubscribe(requests.NewNameTopic, e.nameMgr.InputName)
	// Use all previously discovered names that are in scope
	go e.submitKnownNames()
	go e.submitProvidedNames()

	var addrMgr *AddressManager
	if !e.Config.Passive {
		addrMgr = NewAddressManager(e)
		defer addrMgr.Stop()
		managers = append(managers, addrMgr)
		e.Bus.Subscribe(requests.NameResolvedTopic, addrMgr.InputName)
		defer e.Bus.Unsubscribe(requests.NameResolvedTopic, addrMgr.InputName)
		e.Bus.Subscribe(requests.NewAddrTopic, addrMgr.InputAddress)
		defer e.Bus.Unsubscribe(requests.NewAddrTopic, addrMgr.InputAddress)
		e.Bus.Subscribe(requests.NewASNTopic, e.netCache.Update)
		defer e.Bus.Unsubscribe(requests.NewASNTopic, e.netCache.Update)
	}

	if !e.Config.Passive {
		e.subMgr = NewSubdomainManager(e)
		defer e.subMgr.Stop()
		managers = append(managers, e.subMgr)
		e.Bus.Subscribe(requests.NameResolvedTopic, e.subMgr.InputName)
		defer e.Bus.Unsubscribe(requests.NameResolvedTopic, e.subMgr.InputName)
	}

	if !e.Config.Passive && e.Config.BruteForcing {
		e.bruteMgr = NewBruteManager(e)
		defer e.bruteMgr.Stop()
		managers = append(managers, e.bruteMgr)
	}

	if !e.Config.Passive && e.Config.Alterations {
		e.altMgr = NewAlterationsManager(e)
		defer e.altMgr.Stop()
		managers = append(managers, e.altMgr)
		e.Bus.Subscribe(requests.NameResolvedTopic, e.altMgr.InputName)
		defer e.Bus.Unsubscribe(requests.NameResolvedTopic, e.altMgr.InputName)
	}

	e.domainMgr = NewDomainManager(e)
	defer e.domainMgr.Stop()
	for _, domain := range e.Config.Domains() {
		e.domainMgr.InputName(&requests.DNSRequest{
			Name:   domain,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		})
	}
	managers = append(managers, e.domainMgr)

	if !e.Config.Passive && e.Config.Alterations {
		e.guessMgr = NewGuessManager(e)
		defer e.guessMgr.Stop()
		managers = append(managers, e.guessMgr)
		e.Bus.Subscribe(requests.NameResolvedTopic, e.guessMgr.InputName)
		defer e.Bus.Unsubscribe(requests.NameResolvedTopic, e.guessMgr.InputName)
	}

	e.Bus.Subscribe(requests.OutputTopic, e.sendOutput)
	defer e.Bus.Unsubscribe(requests.OutputTopic, e.sendOutput)
	e.Bus.Subscribe(requests.LogTopic, e.queueLog)
	defer e.Bus.Unsubscribe(requests.LogTopic, e.queueLog)
	e.Bus.Subscribe(requests.SetActiveTopic, e.updateLastActive)
	defer e.Bus.Unsubscribe(requests.SetActiveTopic, e.updateLastActive)
	e.Bus.Subscribe(requests.ResolveCompleted, e.incQueriesPerSec)
	defer e.Bus.Unsubscribe(requests.ResolveCompleted, e.incQueriesPerSec)

	// Setup all core services to receive the appropriate events
register:
	for _, srv := range e.Sys.CoreServices() {
		switch srv.String() {
		case "Data Manager":
			// All requests to the data manager will be sent directly
			continue register
		case "DNS Service":
			e.Bus.Subscribe(requests.ResolveNameTopic, srv.DNSRequest)
			defer e.Bus.Unsubscribe(requests.ResolveNameTopic, srv.DNSRequest)
			e.Bus.Subscribe(requests.SubDiscoveredTopic, srv.SubdomainDiscovered)
			defer e.Bus.Unsubscribe(requests.SubDiscoveredTopic, srv.SubdomainDiscovered)
		default:
			e.Bus.Subscribe(requests.NameRequestTopic, srv.DNSRequest)
			defer e.Bus.Unsubscribe(requests.NameRequestTopic, srv.DNSRequest)
			e.Bus.Subscribe(requests.SubDiscoveredTopic, srv.SubdomainDiscovered)
			defer e.Bus.Unsubscribe(requests.SubDiscoveredTopic, srv.SubdomainDiscovered)
			e.Bus.Subscribe(requests.AddrRequestTopic, srv.AddrRequest)
			defer e.Bus.Unsubscribe(requests.AddrRequestTopic, srv.AddrRequest)
			e.Bus.Subscribe(requests.ASNRequestTopic, srv.ASNRequest)
			defer e.Bus.Unsubscribe(requests.ASNRequestTopic, srv.ASNRequest)
		}
	}

	endChan := make(chan struct{})
	go e.processOutput(endChan)

	t := time.NewTimer(5 * time.Second)
	perMin := time.NewTicker(time.Minute)
	defer perMin.Stop()
loop:
	for {
		select {
		case <-e.done:
			break loop
		case <-t.C:
			num := e.useManagers(managers, 5)
			// Has the enumeration been inactive long enough to stop the task?
			inactive := time.Now().Sub(e.lastActive()) > 15*time.Second

			if num == 0 {
				if inactive {
					// End the enumeration!
					e.Done()
					continue loop
				}

				e.incNumSeqZeros()
			} else {
				e.clearNumSeqZeros()
			}

			e.writeLogs(false)
			t.Reset(5 * time.Second)
		case <-perMin.C:
			if !e.Config.Passive {
				var pct float64
				sec, retries := e.dnsQueriesPerSec()
				if sec > 0 {
					pct = (float64(retries) / float64(sec)) * 100
				}

				e.Config.Log.Printf("Average DNS queries performed: %d/sec, Average retries required: %.2f%%", sec, pct)
				e.clearPerSec()
			}
		}
	}

	cancel()
	<-endChan
	e.writeLogs(true)
	return nil
}

func (e *Enumeration) requiredNumberOfNames(numsec int) int {
	required := numsec
	max := (len(e.Config.Resolvers) * 500) * numsec

	// Calculate the number of names to obtain from the managers
	persec, retries := e.dnsQueriesPerSec()
	if persec > retries {
		sucrate := int(persec) - int(retries)

		// Add 10% more to the success rate to incourage more attempts
		sucrate += sucrate / 10

		// Calc the number of queries that can be performed across the time window
		total := sucrate * numsec

		// Calculate the approximate number of DNS queries already in the works
		remaining := int(e.DNSNamesRemaining())
		if remaining > 0 {
			remaining += e.Config.MaxDNSQueries
		} else {
			// If the queue is empty, then encourage additional activity
			total = max / 2
		}

		// If our total over the time window is larger than the remaining number of
		// DNS queries, then set the required number to our total minus the number remaining
		if remaining < total {
			required = total - remaining

			if required > max {
				required = max
			}
		}
	}

	return required
}

func (e *Enumeration) useManagers(mgrs []FQDNManager, numsec int) int {
	required := 100000

	if !e.Config.Passive {
		required = e.requiredNumberOfNames(numsec)
	}

	var count int
	// Loop through the managers until we acquire the necessary number of names for processing
	for _, mgr := range mgrs {
		remaining := required - count

		reqs := mgr.OutputNames(remaining)
		count += len(reqs)

		// Send the FQDNs acquired from the manager
		for _, req := range reqs {
			if e.Config.Passive {
				e.updateLastActive("enum")
				if e.Config.IsDomainInScope(req.Name) {
					e.Bus.Publish(requests.OutputTopic, eventbus.PriorityLow, &requests.Output{
						Name:   req.Name,
						Domain: req.Domain,
						Tag:    req.Tag,
						Source: req.Source,
					})
				}
				continue
			}

			e.Bus.Publish(requests.ResolveNameTopic, eventbus.PriorityLow, e.ctx, req)
		}

		if count >= required {
			break
		}
	}

	return count
}

func (e *Enumeration) dnsQueriesPerSec() (int64, int64) {
	e.perSecLock.Lock()
	defer e.perSecLock.Unlock()

	if e.perSecLast.After(e.perSecFirst) {
		if sec := e.perSecLast.Sub(e.perSecFirst).Seconds(); sec > 0 {
			div := int64(sec + 1.0)

			return e.perSec / div, e.retries / div
		}
	}

	return 0, 0
}

func (e *Enumeration) incQueriesPerSec(t time.Time, rcode int) {
	go func() {
		e.perSecLock.Lock()
		defer e.perSecLock.Unlock()

		if t.After(e.perSecFirst) {
			e.perSec++

			for _, rc := range resolvers.RetryCodes {
				if rc == rcode {
					e.retries++
					break
				}
			}

			if t.After(e.perSecLast) {
				e.perSecLast = t
			}
		}
	}()
}

func (e *Enumeration) clearPerSec() {
	e.perSecLock.Lock()
	defer e.perSecLock.Unlock()

	e.perSec = 0
	e.retries = 0
	e.perSecFirst = time.Now()
}

// DNSNamesRemaining returns the number of discovered DNS names yet to be handled by the enumeration.
func (e *Enumeration) DNSNamesRemaining() int64 {
	var remaining int

	for _, srv := range e.coreSrvs {
		if srv.String() == "DNS Service" {
			remaining += srv.RequestLen()
			break
		}
	}

	return int64(remaining)
}

func (e *Enumeration) lastActive() time.Time {
	e.lastLock.Lock()
	defer e.lastLock.Unlock()

	return e.last
}

func (e *Enumeration) updateLastActive(srv string) {
	e.lastLock.Lock()
	defer e.lastLock.Unlock()

	// Only update active for core services once we run out of new FQDNs
	if e.numSeqZeros >= 2 {
		var found bool

		for _, s := range e.coreSrvs {
			if srv == s.String() {
				found = true
				break
			}
		}

		if !found {
			return
		}
	}

	// Update the last time activity was seen
	e.last = time.Now()
}

func (e *Enumeration) incNumSeqZeros() {
	e.lastLock.Lock()
	defer e.lastLock.Unlock()

	e.numSeqZeros++
}

func (e *Enumeration) clearNumSeqZeros() {
	e.lastLock.Lock()
	defer e.lastLock.Unlock()

	e.numSeqZeros = 0
}
