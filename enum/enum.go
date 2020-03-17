// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"errors"
	"sync"
	"time"

	alts "github.com/OWASP/Amass/v3/alterations"
	"github.com/OWASP/Amass/v3/config"
	eb "github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/OWASP/Amass/v3/services"
	"github.com/OWASP/Amass/v3/stringset"
)

// Filters contains the set of string filters required during an enumeration.
type Filters struct {
	NewNames      *stringset.StringFilter
	Resolved      *stringset.StringFilter
	NewAddrs      *stringset.StringFilter
	SweepAddrs    *stringset.StringFilter
	Output        *stringset.StringFilter
	PassiveOutput *stringset.StringFilter
}

// Enumeration is the object type used to execute a DNS enumeration with Amass.
type Enumeration struct {
	sync.Mutex

	// Information sent in the context
	Config *config.Config
	Bus    *eb.EventBus
	Sys    services.System

	altState    *alts.State
	markovModel *alts.MarkovModel
	startedAlts bool
	altQueue    *queue.Queue
	moreAlts    chan struct{}

	ctx context.Context

	filters *Filters
	dataMgr services.Service

	startedBrute bool
	bruteQueue   *queue.Queue
	moreBrute    chan struct{}

	srcsLock sync.Mutex
	srcs     stringset.Set

	// Resolved DNS names are put on this queue for output processing
	resolvedQueue *queue.Queue

	// The channel and queue that will receive the results
	Output      chan *requests.Output
	outputQueue *queue.Queue

	// Queue for the log messages
	logQueue *queue.Queue

	// Broadcast channel that indicates no further writes to the output channel
	done   chan struct{}
	closed sync.Once

	// Cache for the infrastructure data collected from online sources
	netCache *net.ASNCache
	netQueue *queue.Queue

	subLock    sync.Mutex
	subdomains map[string]int

	addrsLock sync.Mutex
	addrs     stringset.Set

	lastLock  sync.Mutex
	last      time.Time
	lastPhase time.Time

	perSecLock  sync.Mutex
	perSec      int64
	retries     int64
	perSecFirst time.Time
	perSecLast  time.Time

	pro          interface{ Stop() }
	profileStart sync.Once
}

// NewEnumeration returns an initialized Enumeration that has not been started yet.
func NewEnumeration(sys services.System) *Enumeration {
	e := &Enumeration{
		Config:   config.NewConfig(),
		Bus:      eb.NewEventBus(10000),
		Sys:      sys,
		altQueue: new(queue.Queue),
		moreAlts: make(chan struct{}, 10),
		filters: &Filters{
			NewNames:      stringset.NewStringFilter(),
			Resolved:      stringset.NewStringFilter(),
			NewAddrs:      stringset.NewStringFilter(),
			SweepAddrs:    stringset.NewStringFilter(),
			Output:        stringset.NewStringFilter(),
			PassiveOutput: stringset.NewStringFilter(),
		},
		bruteQueue:    new(queue.Queue),
		moreBrute:     make(chan struct{}, 10),
		srcs:          stringset.New(),
		addrs:         stringset.New(),
		resolvedQueue: new(queue.Queue),
		Output:        make(chan *requests.Output, 1000),
		outputQueue:   new(queue.Queue),
		logQueue:      new(queue.Queue),
		done:          make(chan struct{}),
		netCache:      net.NewASNCache(),
		netQueue:      new(queue.Queue),
		subdomains:    make(map[string]int),
		last:          time.Now(),
		perSecFirst:   time.Now(),
		perSecLast:    time.Now(),
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

	// Setup the DNS name alteration objects
	e.markovModel = alts.NewMarkovModel(3)
	e.altState = alts.NewState(e.Config.AltWordlist)
	e.altState.MinForWordFlip = e.Config.MinForWordFlip
	e.altState.EditDistance = e.Config.EditDistance

	// Setup the context used throughout the enumeration
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, requests.ContextConfig, e.Config)
	e.ctx = context.WithValue(ctx, requests.ContextEventBus, e.Bus)

	e.setupEventBus()

	go e.processAddresses()

	// The enumeration will not terminate until all output has been processed
	startChan := make(chan struct{}, 2)
	endChan := make(chan struct{})
	// Use all previously discovered names that are in scope
	go e.submitKnownNames(startChan)
	go e.submitProvidedNames(startChan)
	go e.processOutput(endChan)

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
		// Release all the domain names specified in the configuration
		for _, domain := range e.Config.Domains() {
			src.DNSRequest(e.ctx, &requests.DNSRequest{
				Name:   domain,
				Domain: domain,
			})
		}
		// Put in requests for all the ASNs specified in the configuration
		for _, asn := range e.Config.ASNs {
			src.ASNRequest(e.ctx, &requests.ASNRequest{ASN: asn})
		}
	}
	e.srcsLock.Unlock()

	var startDone int
	firstMin := true
	e.lastPhase = time.Now()
	twoSec := time.NewTicker(2 * time.Second)
	perMin := time.NewTicker(time.Minute)
loop:
	for {
		select {
		case <-e.done:
			break loop
		case <-startChan:
			startDone++
			if startDone == 2 {
				time.Sleep(10 * time.Second)
			}
		case <-twoSec.C:
			e.releaseAttempts()
			if num := e.logQueue.Len() / 10; num > 0 {
				e.writeLogs(num)
			}
			if startDone >= 2 {
				e.nextPhase(firstMin)
			}
		case <-perMin.C:
			firstMin = false
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

	twoSec.Stop()
	perMin.Stop()
	cancel()
	e.cleanEventBus()
	<-endChan
	e.writeLogs(0)
	return nil
}

func (e *Enumeration) releaseAttempts() {
	remaining := e.DNSNamesRemaining()

	if remaining < 25000 {
		if e.startedBrute {
			for i := 0; i < 5; i++ {
				e.moreBruteForcing()
			}
		}

		if e.startedAlts {
			for i := 0; i < 50; i++ {
				e.moreAlterations()
			}
		}
	}

	time.Sleep(100 * time.Millisecond)
}

func (e *Enumeration) nextPhase(first bool) {
	if time.Now().Before(e.lastPhase.Add(15 * time.Second)) {
		return
	}

	persec, _ := e.dnsQueriesPerSec()
	remaining := e.DNSNamesRemaining()
	// Has the enumeration been inactive long enough to stop the task?
	inactive := time.Now().Sub(e.lastActive()) > 5*time.Second

	if persec > 1000 && remaining > 25000 {
		return
	}

	bruteReady := !e.Config.Passive && e.Config.BruteForcing && !e.startedBrute
	altsReady := !e.Config.Passive && e.Config.Alterations && !e.startedAlts

	if bruteReady {
		e.startedBrute = true
		go e.startBruteForcing()

		for i := 0; i < 10; i++ {
			e.moreBruteForcing()
		}

		e.Config.Log.Print("Starting DNS queries for brute forcing")
		e.lastPhase = time.Now()
	} else if altsReady {
		e.startedAlts = true
		go e.performAlterations()

		for i := 0; i < 100; i++ {
			e.moreAlterations()
		}

		e.Config.Log.Print("Starting DNS queries for altered names")
		e.lastPhase = time.Now()
	} else if !first && inactive && persec < 50 {
		// End the enumeration!
		e.Done()
	}
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

	for _, srv := range e.Sys.CoreServices() {
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
	go func() {
		e.lastLock.Lock()
		defer e.lastLock.Unlock()

		e.last = time.Now()
	}()
}

func (e *Enumeration) setupEventBus() {
	e.Bus.Subscribe(requests.OutputTopic, e.sendOutput)
	e.Bus.Subscribe(requests.LogTopic, e.queueLog)
	e.Bus.Subscribe(requests.SetActiveTopic, e.updateLastActive)
	e.Bus.Subscribe(requests.ResolveCompleted, e.incQueriesPerSec)

	e.Bus.Subscribe(requests.NewNameTopic, e.newNECallback)

	if !e.Config.Passive {
		e.Bus.Subscribe(requests.NameResolvedTopic, e.newRNCallback)

		e.Bus.Subscribe(requests.NewAddrTopic, e.newAddress)
		e.Bus.Subscribe(requests.NewASNTopic, e.netCache.Update)
	}

	// Setup all core services to receive the appropriate events
loop:
	for _, srv := range e.Sys.CoreServices() {
		switch srv.String() {
		case "Data Manager":
			// All requests to the data manager will be sent directly
			continue loop
		case "DNS Service":
			e.Bus.Subscribe(requests.ResolveNameTopic, srv.DNSRequest)
			e.Bus.Subscribe(requests.SubDiscoveredTopic, srv.SubdomainDiscovered)
		default:
			e.Bus.Subscribe(requests.NameRequestTopic, srv.DNSRequest)
			e.Bus.Subscribe(requests.SubDiscoveredTopic, srv.SubdomainDiscovered)
			e.Bus.Subscribe(requests.AddrRequestTopic, srv.AddrRequest)
			e.Bus.Subscribe(requests.ASNRequestTopic, srv.ASNRequest)
		}
	}
}

func (e *Enumeration) cleanEventBus() {
	e.Bus.Unsubscribe(requests.OutputTopic, e.sendOutput)
	e.Bus.Unsubscribe(requests.LogTopic, e.queueLog)
	e.Bus.Unsubscribe(requests.SetActiveTopic, e.updateLastActive)
	e.Bus.Unsubscribe(requests.ResolveCompleted, e.incQueriesPerSec)

	e.Bus.Unsubscribe(requests.NewNameTopic, e.newNECallback)

	if !e.Config.Passive {
		e.Bus.Unsubscribe(requests.NameResolvedTopic, e.newRNCallback)

		e.Bus.Unsubscribe(requests.NewAddrTopic, e.newAddress)
		e.Bus.Unsubscribe(requests.NewASNTopic, e.netCache.Update)
	}

	// Setup all core services to receive the appropriate events
loop:
	for _, srv := range e.Sys.CoreServices() {
		switch srv.String() {
		case "Data Manager":
			// All requests to the data manager will be sent directly
			continue loop
		case "DNS Service":
			e.Bus.Unsubscribe(requests.ResolveNameTopic, srv.DNSRequest)
			e.Bus.Unsubscribe(requests.SubDiscoveredTopic, srv.SubdomainDiscovered)
		default:
			e.Bus.Unsubscribe(requests.NameRequestTopic, srv.DNSRequest)
			e.Bus.Unsubscribe(requests.SubDiscoveredTopic, srv.SubdomainDiscovered)
			e.Bus.Unsubscribe(requests.AddrRequestTopic, srv.AddrRequest)
			e.Bus.Unsubscribe(requests.ASNRequestTopic, srv.ASNRequest)
		}
	}
}
