// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/graphdb"
	"github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/OWASP/Amass/v3/stringfilter"
	"github.com/OWASP/Amass/v3/stringset"
	"github.com/OWASP/Amass/v3/systems"
)

var filterMaxSize int64 = 1 << 24

// Enumeration is the object type used to execute a DNS enumeration with Amass.
type Enumeration struct {
	// Information sent in the context
	Config     *config.Config
	Bus        *eventbus.EventBus
	Sys        systems.System
	Graph      *graph.Graph
	closedOnce sync.Once

	ctx context.Context

	dnsMgr       requests.Service
	dataMgr      requests.Service
	dataMgrEmpty bool
	dataMgrLock  sync.Mutex

	srcsLock sync.Mutex
	srcs     stringset.Set

	// The filter for new outgoing DNS queries
	resFilter      stringfilter.Filter
	resFilterCount int64

	// Queue for the log messages
	logQueue *queue.Queue

	// Broadcast channel that indicates no further writes to the output channel
	done     chan struct{}
	doneOnce sync.Once

	// Cache for the infrastructure data collected from online sources
	netCache *net.ASNCache

	managers       []FQDNManager
	resolvedMgrs   []FQDNManager
	resolvedFilter stringfilter.Filter
	nameMgr        *NameManager
	subMgr         *SubdomainManager
	bruteMgr       *BruteManager
	altMgr         *AlterationsManager
	guessMgr       *GuessManager
	domainMgr      *DomainManager

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
func NewEnumeration(cfg *config.Config, sys systems.System) *Enumeration {
	e := &Enumeration{
		Config:         cfg,
		Sys:            sys,
		Bus:            eventbus.NewEventBus(100000),
		Graph:          graph.NewGraph(graphdb.NewCayleyGraphMemory()),
		srcs:           stringset.New(),
		resFilter:      stringfilter.NewBloomFilter(filterMaxSize),
		logQueue:       new(queue.Queue),
		done:           make(chan struct{}),
		netCache:       net.NewASNCache(),
		resolvedFilter: stringfilter.NewBloomFilter(filterMaxSize),
		last:           time.Now(),
		dataMgrEmpty:   true,
		perSecFirst:    time.Now(),
		perSecLast:     time.Now(),
	}

	if cfg.Passive {
		return e
	}

	e.dataMgr = NewDataManagerService(sys, e.Graph)
	if err := e.dataMgr.Start(); err != nil {
		return nil
	}

	e.dnsMgr = NewDNSService(sys)
	if err := e.dnsMgr.Start(); err != nil {
		return nil
	}

	return e
}

// Close cleans up resources instantiated by the Enumeration.
func (e *Enumeration) Close() {
	e.closedOnce.Do(func() {
		e.Graph.Close()
	})
}

// Done safely closes the done broadcast channel.
func (e *Enumeration) Done() {
	e.doneOnce.Do(func() {
		close(e.done)
	})
}

// Start begins the vertical domain correlation process for the Enumeration object.
func (e *Enumeration) Start() error {
	if err := e.Config.CheckSettings(); err != nil {
		return err
	}

	// Using the configuration provided, this section determines
	// which data sources will be used in the enumeration
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

	/*
	 * This context, used throughout the enumeration, will provide the
	 * ability to cancel operations and to pass the configuration and
	 * event bus to all the components
	 */
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, requests.ContextConfig, e.Config)
	e.ctx = context.WithValue(ctx, requests.ContextEventBus, e.Bus)

	// Start the logging at this point, since data sources are used shortly
	go e.periodicLogging()

	// If requests were made for specific ASNs, then those requests are
	// send to included data sources at this point
	e.srcsLock.Lock()
	for _, src := range e.Sys.DataSources() {
		if !e.srcs.Has(src.String()) {
			continue
		}

		for _, asn := range e.Config.ASNs {
			src.ASNRequest(e.ctx, &requests.ASNRequest{ASN: asn})
		}
	}
	e.srcsLock.Unlock()

	/*
	 * A sequence of name managers is setup starting here. This sequence of
	 * managers will be used throughout the enumeration to control the
	 * release and handle the discovery of new names. The order that the
	 * managers have been entered into the sequence is important to how the
	 * engine selects which names to process next during the enumeration
	 */

	/*
	 * Setup the NameManager for receiving newly discovered names from the
	 * event bus NewNameTopic. This manager is essential, even for passive
	 * mode
	 */
	e.nameMgr = NewNameManager(e)
	defer e.nameMgr.Stop()
	e.managers = append(e.managers, e.nameMgr)
	e.Bus.Subscribe(requests.NewNameTopic, e.nameMgr.InputName)
	defer e.Bus.Unsubscribe(requests.NewNameTopic, e.nameMgr.InputName)

	/*
	 * Now that the NameManager has been setup, names provided by the user
	 * and names acquired from the graph database can be brought into the
	 * enumeration
	 */
	go e.submitKnownNames()
	go e.submitProvidedNames()

	/*
	 * When not running in passive mode, the enumeration will require an
	 * AddressManager to receive successfully resolved FQDNs and process
	 * the IP addresses for caching of infrastructure data, setting up
	 * reverse DNS queries, and other engagements when in active mode
	 */
	var addrMgr *AddressManager
	if !e.Config.Passive {
		addrMgr = NewAddressManager(e)
		defer addrMgr.Stop()
		e.managers = append(e.managers, addrMgr)
		e.resolvedMgrs = append(e.resolvedMgrs, addrMgr)
		e.Bus.Subscribe(requests.NewAddrTopic, addrMgr.InputAddress)
		defer e.Bus.Unsubscribe(requests.NewAddrTopic, addrMgr.InputAddress)
		e.Bus.Subscribe(requests.NewASNTopic, e.netCache.Update)
		defer e.Bus.Unsubscribe(requests.NewASNTopic, e.netCache.Update)
	}

	/*
	 * When not running in passive mode, the enumeration will need to keep
	 * track of all proper subdomain names found and how many unique labals
	 * each subdomain has. This information is important for other operations
	 * such as brute forcing and attempts to guess new FQDNs
	 */
	if !e.Config.Passive {
		e.subMgr = NewSubdomainManager(e)
		defer e.subMgr.Stop()
		e.managers = append(e.managers, e.subMgr)
		e.resolvedMgrs = append(e.resolvedMgrs, e.subMgr)
	}

	/*
	 * If the user has requested brute forcing and we are not in passive mode,
	 * then the enumeration will need a BruteManager to handle the use of
	 * wordlists to generate new names for DNS resolution
	 */
	if !e.Config.Passive && e.Config.BruteForcing {
		e.bruteMgr = NewBruteManager(e)
		defer e.bruteMgr.Stop()
		e.managers = append(e.managers, e.bruteMgr)
	}

	/*
	 * When not running in passive mode, the generation of permuted names is
	 * on by default, and requires an AlterationsManager in order to manage
	 * newly discovered names that can now be altered
	 */
	if !e.Config.Passive && e.Config.Alterations {
		e.altMgr = NewAlterationsManager(e)
		defer e.altMgr.Stop()
		e.managers = append(e.managers, e.altMgr)
		e.resolvedMgrs = append(e.resolvedMgrs, e.altMgr)
	}

	/*
	 * Setup the DomainManager for releasing root domain names that are in
	 * scope and identified by the user. This manager is essential, even for
	 * passive mode
	 */
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
	e.managers = append(e.managers, e.domainMgr)

	/*
	 * When not running in passive mode, the generation of permuted names is
	 * on by default, and requires a GuessManager in order to manage newly
	 * discovered names that will train the machine learning system and to
	 * release the similar names generated by the algorithm
	 */
	if !e.Config.Passive && e.Config.Alterations {
		e.guessMgr = NewGuessManager(e)
		defer e.guessMgr.Stop()
		e.managers = append(e.managers, e.guessMgr)
		e.resolvedMgrs = append(e.resolvedMgrs, e.guessMgr)
	}

	// Setup the event handler for newly resolved DNS names
	e.Bus.Subscribe(requests.NameResolvedTopic, e.resolvedDispatcher)
	defer e.Bus.Unsubscribe(requests.NameResolvedTopic, e.resolvedDispatcher)

	/*
	 * These events are important to the engine in order to receive output, logs,
	 * notices about service activity, and notices about DNS query completion
	 */
	e.Bus.Subscribe(requests.LogTopic, e.queueLog)
	defer e.Bus.Unsubscribe(requests.LogTopic, e.queueLog)
	e.Bus.Subscribe(requests.SetActiveTopic, e.updateLastActive)
	defer e.Bus.Unsubscribe(requests.SetActiveTopic, e.updateLastActive)
	e.Bus.Subscribe(requests.ResolveCompleted, e.incQueriesPerSec)
	defer e.Bus.Unsubscribe(requests.ResolveCompleted, e.incQueriesPerSec)

	// Setup the DNS Service to receive the appropriate events
	if !e.Config.Passive {
		e.Bus.Subscribe(requests.ResolveNameTopic, e.dnsMgr.DNSRequest)
		defer e.Bus.Unsubscribe(requests.ResolveNameTopic, e.dnsMgr.DNSRequest)
		e.Bus.Subscribe(requests.SubDiscoveredTopic, e.dnsMgr.SubdomainDiscovered)
		defer e.Bus.Unsubscribe(requests.SubDiscoveredTopic, e.dnsMgr.SubdomainDiscovered)
	}

	// If a timeout was provided in the configuration, it will go off that
	// many minutes from this point in the enumeration process
	if e.Config.Timeout > 0 {
		time.AfterFunc(time.Duration(e.Config.Timeout)*time.Minute, func() {
			e.Config.Log.Printf("Enumeration exceeded provided timeout")
			e.Done()
		})
	}

	secDelay := 5
	t := time.NewTimer(time.Duration(secDelay) * time.Second)
	perMin := time.NewTicker(time.Minute)
	defer perMin.Stop()
loop:
	for {
		select {
		case <-e.done:
			break loop
		case <-t.C:
			num := e.useManagers(secDelay)

			var inactive bool
			e.dataMgrLock.Lock()
			empty := e.dataMgrEmpty
			e.dataMgrLock.Unlock()
			// Has the enumeration been inactive long enough to stop the task?
			if empty {
				inactive = time.Now().Sub(e.lastActive()) > 15*time.Second
			}

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

			t.Reset(time.Duration(secDelay) * time.Second)
		case <-perMin.C:
			if !e.Config.Passive {
				var pct float64
				sec, retries := e.dnsQueriesPerSec()
				if sec > 0 {
					pct = (float64(retries) / float64(sec)) * 100
				}

				e.Config.Log.Printf("Average DNS queries performed: %d/sec, Average retries required: %.2f%%", sec, pct)
				e.clearPerSec()
				go e.isDataManagerQueueEmpty()
			}
		}
	}

	cancel()
	if !e.Config.Passive {
		e.dnsMgr.Stop()
		e.dataMgr.Stop()
	}
	e.writeLogs(true)
	// Attempt to fix IP address nodes without edges to netblocks
	e.Graph.HealAddressNodes(e.netCache, e.Config.UUID.String())
	return nil
}

func (e *Enumeration) isDataManagerQueueEmpty() {
	empty := e.dataMgr.RequestLen() == 0

	e.dataMgrLock.Lock()
	e.dataMgrEmpty = empty
	e.dataMgrLock.Unlock()
}

func (e *Enumeration) resolvedDispatcher(req *requests.DNSRequest) {
	if e.resolvedFilter.Duplicate(req.Name) {
		return
	}

	for _, mgr := range e.resolvedMgrs {
		go mgr.InputName(req)
	}
}

func (e *Enumeration) requiredNumberOfNames(numsec int) int {
	required := 10000
	if e.Config.Passive {
		return required
	}

	max := e.Config.MaxDNSQueries * numsec
	// Acquire the number of DNS queries already in the queue
	remaining := e.dnsNamesRemaining()
	if remaining > 0 {
		required = max - remaining
	} else {
		// If the queue is empty, then encourage additional activity
		required = max
	}

	// Ensure a minimum value of one
	if required <= 0 {
		required = 1
	}

	return required
}

func (e *Enumeration) useManagers(numsec int) int {
	required := e.requiredNumberOfNames(numsec)

	var count int
	// Loop through the managers until we acquire the necessary number of names for processing
	for _, mgr := range e.managers {
		remaining := required - count

		var reqs []*requests.DNSRequest
		for _, req := range mgr.OutputNames(remaining) {
			// Do not submit names from untrusted sources, after
			// already receiving the name from a trusted source
			if !requests.TrustedTag(req.Tag) && e.resFilter.Has(req.Name+strconv.FormatBool(true)) {
				continue
			}

			// At most, a FQDN will be accepted from an untrusted source first,
			// and then reconsidered from a trusted data source
			if e.resFilter.Duplicate(req.Name + strconv.FormatBool(requests.TrustedTag(req.Tag))) {
				continue
			}

			// Check if it's time to reset our bloom filter due to number of elements seen
			e.resFilterCount++
			if e.resFilterCount >= filterMaxSize {
				e.resFilterCount = 0
				e.resFilter = stringfilter.NewBloomFilter(filterMaxSize)
			}

			count++
			reqs = append(reqs, req)
		}

		// Send the FQDNs acquired from the manager
		for _, req := range reqs {
			if e.Config.Passive {
				e.updateLastActive("enum")
				if e.Config.IsDomainInScope(req.Name) {
					e.Graph.InsertFQDN(req.Name, req.Source, req.Tag, e.Config.UUID.String())
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

func (e *Enumeration) dnsNamesRemaining() int {
	return e.dnsMgr.RequestLen()
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

		for _, s := range []requests.Service{e.dnsMgr, e.dataMgr} {
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
