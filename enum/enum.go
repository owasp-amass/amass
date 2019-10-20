// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	alts "github.com/OWASP/Amass/alterations"
	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/graph"
	amassdns "github.com/OWASP/Amass/net/dns"
	"github.com/OWASP/Amass/queue"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/services"
	sf "github.com/OWASP/Amass/stringfilter"
	"github.com/OWASP/Amass/stringset"
	"github.com/miekg/dns"
)

var topNames = []string{
	"www",
	"online",
	"webserver",
	"ns1",
	"mail",
	"smtp",
	"webmail",
	"prod",
	"test",
	"vpn",
	"ftp",
	"ssh",
}

// Filters contains the set of string filters required during an enumeration.
type Filters struct {
	NewNames      *sf.StringFilter
	Resolved      *sf.StringFilter
	NewAddrs      *sf.StringFilter
	SweepAddrs    *sf.StringFilter
	Output        *sf.StringFilter
	PassiveOutput *sf.StringFilter
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

	ctx context.Context

	filters *Filters
	dataMgr services.Service

	startedBrute bool
	bruteQueue   *queue.Queue

	srcsLock sync.Mutex
	srcs     stringset.Set

	// The channel and queue that will receive the results
	Output      chan *requests.Output
	outputQueue *queue.Queue

	// Queue for the log messages
	logQueue *queue.Queue

	// Broadcast channel that indicates no further writes to the output channel
	done              chan struct{}
	doneAlreadyClosed bool

	// Cache for the infrastructure data collected from online sources
	netLock  sync.Mutex
	netCache map[int]*requests.ASNRequest
	netQueue *queue.Queue

	subLock    sync.Mutex
	subdomains map[string]int

	lastLock sync.Mutex
	last     time.Time

	perSecLock  sync.Mutex
	perSec      int64
	perSecFirst time.Time
	perSecLast  time.Time
}

// NewEnumeration returns an initialized Enumeration that has not been started yet.
func NewEnumeration(sys services.System) *Enumeration {
	e := &Enumeration{
		Config:   config.NewConfig(),
		Bus:      eb.NewEventBus(),
		Sys:      sys,
		altQueue: new(queue.Queue),
		filters: &Filters{
			NewNames:      sf.NewStringFilter(),
			Resolved:      sf.NewStringFilter(),
			NewAddrs:      sf.NewStringFilter(),
			SweepAddrs:    sf.NewStringFilter(),
			Output:        sf.NewStringFilter(),
			PassiveOutput: sf.NewStringFilter(),
		},
		bruteQueue:  new(queue.Queue),
		srcs:        stringset.New(),
		Output:      make(chan *requests.Output, 100),
		outputQueue: new(queue.Queue),
		logQueue:    new(queue.Queue),
		done:        make(chan struct{}, 2),
		netCache:    make(map[int]*requests.ASNRequest),
		netQueue:    new(queue.Queue),
		subdomains:  make(map[string]int),
		last:        time.Now(),
		perSecFirst: time.Now(),
		perSecLast:  time.Now(),
	}

	if ref := e.refToDataManager(); ref != nil {
		e.dataMgr = ref
		return e
	}
	return nil
}

// Done safely closes the done broadcast channel.
func (e *Enumeration) Done() {
	e.Lock()
	defer e.Unlock()

	if !e.doneAlreadyClosed {
		e.doneAlreadyClosed = true
		close(e.done)
	}
}

// Start begins the DNS enumeration process for the Amass Enumeration object.
func (e *Enumeration) Start() error {
	if e.Output == nil {
		return errors.New("The enumeration did not have an output channel")
	} else if e.Config.Passive && e.Config.DataOptsWriter != nil {
		return errors.New("Data operations cannot be saved without DNS resolution")
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
	var wg sync.WaitGroup
	wg.Add(4)
	// Use all previously discovered names that are in scope
	go e.submitKnownNames(&wg)
	go e.submitProvidedNames(&wg)
	go e.checkForOutput(&wg)
	go e.processOutput(&wg)

	if e.Config.Timeout > 0 {
		time.AfterFunc(time.Duration(e.Config.Timeout)*time.Minute, func() {
			e.Config.Log.Printf("Enumeration exceeded provided timeout")
			e.Done()
		})
	}

	// Release all the domain names specified in the configuration
	e.srcsLock.Lock()
	for _, src := range e.Sys.DataSources() {
		if !e.srcs.Has(src.String()) {
			continue
		}

		for _, domain := range e.Config.Domains() {
			// Send each root domain name
			src.DNSRequest(e.ctx, &requests.DNSRequest{
				Name:   domain,
				Domain: domain,
			})
		}
	}

	// Put in requests for all the ASNs specified in the configuration
	for _, src := range e.Sys.DataSources() {
		if !e.srcs.Has(src.String()) {
			continue
		}

		for _, asn := range e.Config.ASNs {
			src.ASNRequest(e.ctx, &requests.ASNRequest{ASN: asn})
		}
	}
	e.srcsLock.Unlock()

	t := time.NewTicker(2 * time.Second)
	logTick := time.NewTicker(time.Minute)
loop:
	for {
		select {
		case <-e.done:
			break loop
		case <-t.C:
			e.writeLogs()

			// Has the enumeration been inactive long enough to stop the task?
			if inactive := time.Now().Sub(e.lastActive()); inactive > 5*time.Second {
				e.nextPhase(true)
				time.Sleep(time.Second)
			}
		case <-logTick.C:
			if !e.Config.Passive {
				remaining := e.DNSNamesRemaining()

				e.Config.Log.Printf("Average DNS queries performed: %d/sec, DNS names queued: %d",
					e.DNSQueriesPerSec(), remaining)
				e.clearPerSec()

				// Does the enumeration need more names to process?
				if !e.Config.Passive && remaining < 1000 {
					e.nextPhase(false)
					time.Sleep(time.Second)
				}
			}
		}
	}
	t.Stop()
	logTick.Stop()
	cancel()
	e.cleanEventBus()
	time.Sleep(2 * time.Second)
	wg.Wait()
	e.writeLogs()
	return nil
}

func (e *Enumeration) nextPhase(inactive bool) {
	if !e.Config.Passive && e.Config.BruteForcing && !e.startedBrute {
		e.startedBrute = true
		go e.startBruteForcing()
		e.Config.Log.Print("Starting DNS queries for brute forcing")
	} else if !e.Config.Passive && e.Config.Alterations && !e.startedAlts {
		e.startedAlts = true
		go e.performAlterations()
		e.Config.Log.Print("Starting DNS queries for altered names")
	} else if inactive {
		// Could be showing as inactive, but DNS queries are not finished
		if !e.Config.Passive && e.DNSQueriesPerSec() >= 10 {
			return
		}
		// End the enumeration!
		e.Done()
	}
}

func (e *Enumeration) lastActive() time.Time {
	e.lastLock.Lock()
	defer e.lastLock.Unlock()

	return e.last
}

func (e *Enumeration) updateLastActive(srv string) {
	e.lastLock.Lock()
	defer e.lastLock.Unlock()

	e.last = time.Now()
}

func (e *Enumeration) newASN(req *requests.ASNRequest) {
	e.updateConfigWithNetblocks(req)
	e.updateASNCache(req)
}

func (e *Enumeration) setupEventBus() {
	e.Bus.Subscribe(requests.OutputTopic, e.sendOutput)
	e.Bus.Subscribe(requests.LogTopic, e.queueLog)
	e.Bus.Subscribe(requests.SetActiveTopic, e.updateLastActive)
	e.Bus.Subscribe(requests.ResolveCompleted, e.incQueriesPerSec)

	e.Bus.Subscribe(requests.NewNameTopic, e.newNameEvent)

	if !e.Config.Passive {
		e.Bus.Subscribe(requests.NameResolvedTopic, e.newResolvedName)

		e.Bus.Subscribe(requests.NewAddrTopic, e.newAddress)
		e.Bus.Subscribe(requests.NewASNTopic, e.newASN)
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

	e.Bus.Unsubscribe(requests.NewNameTopic, e.newNameEvent)

	if !e.Config.Passive {
		e.Bus.Unsubscribe(requests.NameResolvedTopic, e.newResolvedName)

		e.Bus.Unsubscribe(requests.NewAddrTopic, e.newAddress)
		e.Bus.Unsubscribe(requests.NewASNTopic, e.newASN)
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

func (e *Enumeration) newNameEvent(req *requests.DNSRequest) {
	if req == nil || req.Name == "" || req.Domain == "" {
		return
	}

	req.Name = strings.ToLower(amassdns.RemoveAsteriskLabel(req.Name))
	req.Name = strings.Trim(req.Name, ".")
	req.Domain = strings.ToLower(req.Domain)

	// Filter on the DNS name + the value from TrustedTag
	if e.filters.NewNames.Duplicate(req.Name +
		strconv.FormatBool(requests.TrustedTag(req.Tag))) {
		return
	}

	if e.Config.Passive {
		e.updateLastActive("enum")
		if e.Config.IsDomainInScope(req.Name) {
			e.Bus.Publish(requests.OutputTopic, &requests.Output{
				Name:   req.Name,
				Domain: req.Domain,
				Tag:    req.Tag,
				Source: req.Source,
			})
		}
		return
	}

	e.Bus.Publish(requests.ResolveNameTopic, e.ctx, req)
}

func (e *Enumeration) newResolvedName(req *requests.DNSRequest) {
	req.Name = strings.ToLower(amassdns.RemoveAsteriskLabel(req.Name))
	req.Name = strings.Trim(req.Name, ".")
	req.Domain = strings.ToLower(req.Domain)

	// Write the DNS name information to the graph databases
	e.dataMgr.DNSRequest(e.ctx, req)

	/*
	 * Do not go further if the name is not in scope or been seen before
	 */
	if e.filters.Resolved.Duplicate(req.Name) ||
		!e.Config.IsDomainInScope(req.Name) {
		return
	}

	// Keep track of all domains and proper subdomains discovered
	e.checkSubdomain(req)

	if e.Config.BruteForcing && e.Config.Recursive {
		for _, name := range topNames {
			e.newNameEvent(&requests.DNSRequest{
				Name:   name + "." + req.Name,
				Domain: req.Domain,
				Tag:    requests.BRUTE,
				Source: "Enum Probes",
			})
		}
	}

	// Queue the resolved name for future brute forcing
	if e.Config.BruteForcing && e.Config.Recursive && (e.Config.MinForRecursive == 0) {
		// Do not send in the resolved root domain names
		if len(strings.Split(req.Name, ".")) != len(strings.Split(req.Domain, ".")) {
			e.bruteQueue.Append(req)
		}
	}

	// Queue the name and domain for future name alterations
	if e.Config.Alterations {
		e.altQueue.Append(req)
	}

	e.srcsLock.Lock()
	defer e.srcsLock.Unlock()

	for _, srv := range e.Sys.DataSources() {
		// Call DNSRequest for all web archive services
		if srv.Type() == requests.ARCHIVE && e.srcs.Has(srv.String()) {
			srv.DNSRequest(e.ctx, req)
		}
	}
}

func (e *Enumeration) checkSubdomain(req *requests.DNSRequest) {
	labels := strings.Split(req.Name, ".")
	num := len(labels)
	// Is this large enough to consider further?
	if num < 2 {
		return
	}
	// It cannot have fewer labels than the root domain name
	if num-1 < len(strings.Split(req.Domain, ".")) {
		return
	}
	// Do not further evaluate service subdomains
	if labels[1] == "_tcp" || labels[1] == "_udp" || labels[1] == "_tls" {
		return
	}

	sub := strings.Join(labels[1:], ".")

	for _, g := range e.Sys.GraphDatabases() {
		// CNAMEs are not a proper subdomain
		cname := g.IsCNAMENode(&graph.DataOptsParams{
			UUID:   e.Config.UUID.String(),
			Name:   sub,
			Domain: req.Domain,
		})
		if cname {
			return
		}
	}

	r := &requests.DNSRequest{
		Name:   sub,
		Domain: req.Domain,
		Tag:    req.Tag,
		Source: req.Source,
	}
	times := e.timesForSubdomain(sub)

	e.Bus.Publish(requests.SubDiscoveredTopic, e.ctx, r, times)
	// Queue the proper subdomain for future brute forcing
	if e.Config.BruteForcing && e.Config.Recursive &&
		e.Config.MinForRecursive > 0 && e.Config.MinForRecursive == times {
		e.bruteQueue.Append(r)
	}
	// Check if the subdomain should be added to the markov model
	if e.Config.Alterations && times == 1 {
		e.markovModel.AddSubdomain(sub)
	}

	e.srcsLock.Lock()
	defer e.srcsLock.Unlock()

	// Let all the data sources know about the discovered proper subdomain
	for _, src := range e.Sys.DataSources() {
		if e.srcs.Has(src.String()) {
			src.SubdomainDiscovered(e.ctx, r, times)
		}
	}
}

func (e *Enumeration) timesForSubdomain(sub string) int {
	e.subLock.Lock()
	defer e.subLock.Unlock()

	times, found := e.subdomains[sub]
	if found {
		times++
	} else {
		times = 1
	}

	e.subdomains[sub] = times
	return times
}

func (e *Enumeration) newAddress(req *requests.AddrRequest) {
	if req == nil || req.Address == "" {
		return
	}

	if e.filters.NewAddrs.Duplicate(req.Address) {
		return
	}

	if e.Config.Active {
		e.namesFromCertificates(req.Address)
	}

	// See if the required ASN information is already in the cache
	asn := e.ipSearch(req.Address)
	if asn != nil {
		// Write the ASN information to the graph databases
		e.dataMgr.ASNRequest(e.ctx, asn)

		// Perform the reverse DNS sweep if the IP address is in scope
		if e.Config.IsDomainInScope(req.Domain) {
			if _, cidr, _ := net.ParseCIDR(asn.Prefix); cidr != nil {
				e.reverseDNSSweep(req.Address, cidr)
			}
		}
		return
	}

	// Query the data sources for ASN information related to this IP address
	e.srcsLock.Lock()
	for _, src := range e.Sys.DataSources() {
		if e.srcs.Has(src.String()) {
			src.ASNRequest(e.ctx, &requests.ASNRequest{Address: req.Address})
		}
	}
	e.srcsLock.Unlock()

	// Wait a bit and then send the AddrRequest along for processing
	time.Sleep(3 * time.Second)
	e.netQueue.Append(req)
}

func (e *Enumeration) processAddresses() {
	curIdx := 0
	maxIdx := 7
	delays := []int{10, 25, 50, 75, 100, 150, 250, 500}
loop:
	for {
		select {
		case <-e.done:
			return
		default:
			element, ok := e.netQueue.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue loop
			}

			curIdx = 0
			req := element.(*requests.AddrRequest)

			asn := e.ipSearch(req.Address)
			if asn == nil {
				time.Sleep(time.Second)
				e.netQueue.Append(req)
				continue loop
			}

			// Write the ASN information to the graph databases
			e.dataMgr.ASNRequest(e.ctx, asn)

			// Perform the reverse DNS sweep if the IP address is in scope
			if e.Config.IsDomainInScope(req.Domain) {
				if _, cidr, _ := net.ParseCIDR(asn.Prefix); cidr != nil {
					go e.reverseDNSSweep(req.Address, cidr)
				}
			}
		}
	}
}

func (e *Enumeration) submitKnownNames(wg *sync.WaitGroup) {
	defer wg.Done()
	for _, g := range e.Sys.GraphDatabases() {
		for _, enum := range g.EnumerationList() {
			var found bool

			for _, domain := range g.EnumerationDomains(enum) {
				if e.Config.IsDomainInScope(domain) {
					found = true
					break
				}
			}
			if !found {
				continue
			}

			for _, o := range g.GetOutput(enum, true) {
				if e.Config.IsDomainInScope(o.Name) {
					e.Bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
						Name:   o.Name,
						Domain: o.Domain,
						Tag:    requests.EXTERNAL,
						Source: "Previous Enum",
					})
				}
			}
		}
	}
}

func (e *Enumeration) submitProvidedNames(wg *sync.WaitGroup) {
	defer wg.Done()
	for _, name := range e.Config.ProvidedNames {
		if domain := e.Config.WhichDomain(name); domain != "" {
			e.Bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    requests.EXTERNAL,
				Source: "User Input",
			})
		}
	}
}

func (e *Enumeration) startBruteForcing() {
	// Send in the root domain names for brute forcing
	for _, domain := range e.Config.Domains() {
		e.bruteSendNewNames(&requests.DNSRequest{
			Name:   domain,
			Domain: domain,
		})
	}

	curIdx := 0
	maxIdx := 7
	delays := []int{10, 25, 50, 75, 100, 150, 250, 500}
loop:
	for {
		select {
		case <-e.done:
			return
		default:
			element, ok := e.bruteQueue.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue loop
			}

			curIdx = 0
			req := element.(*requests.DNSRequest)
			e.bruteSendNewNames(req)
		}
	}
}

func (e *Enumeration) bruteSendNewNames(req *requests.DNSRequest) {
	if !e.Config.IsDomainInScope(req.Name) {
		return
	}

	if len(req.Records) > 0 {
		var ok bool

		for _, r := range req.Records {
			t := uint16(r.Type)

			if t == dns.TypeA || t == dns.TypeAAAA {
				ok = true
				break
			}
		}

		if !ok {
			return
		}
	}

	subdomain := strings.ToLower(req.Name)
	domain := strings.ToLower(req.Domain)
	if subdomain == "" || domain == "" {
		return
	}

	for _, g := range e.Sys.GraphDatabases() {
		// CNAMEs are not a proper subdomain
		cname := g.IsCNAMENode(&graph.DataOptsParams{
			UUID:   e.Config.UUID.String(),
			Name:   subdomain,
			Domain: domain,
		})
		if cname {
			return
		}
	}

	for _, word := range e.Config.Wordlist {
		if word == "" {
			continue
		}

		e.newNameEvent(&requests.DNSRequest{
			Name:   word + "." + subdomain,
			Domain: domain,
			Tag:    requests.BRUTE,
			Source: "Brute Forcing",
		})
	}
}

func (e *Enumeration) performAlterations() {
	curIdx := 0
	maxIdx := 7
	delays := []int{10, 25, 50, 75, 100, 150, 250, 500}
loop:
	for {
		select {
		case <-e.done:
			return
		default:
			element, ok := e.altQueue.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue loop
			}

			curIdx = 0
			req := element.(*requests.DNSRequest)

			if !e.Config.IsDomainInScope(req.Name) ||
				(len(strings.Split(req.Domain, ".")) == len(strings.Split(req.Name, "."))) {
				continue loop
			}

			for _, g := range e.Sys.GraphDatabases() {
				// CNAMEs are not a proper subdomain
				cname := g.IsCNAMENode(&graph.DataOptsParams{
					UUID:   e.Config.UUID.String(),
					Name:   req.Name,
					Domain: req.Domain,
				})
				if cname {
					continue loop
				}
			}

			newNames := stringset.New()

			e.markovModel.Train(req.Name)
			if e.markovModel.TotalTrainings() >= 50 &&
				(e.markovModel.TotalTrainings()%10 == 0) {
				newNames.InsertMany(e.markovModel.GenerateNames(100)...)
			}

			if e.Config.FlipNumbers {
				newNames.InsertMany(e.altState.FlipNumbers(req.Name)...)
			}
			if e.Config.AddNumbers {
				newNames.InsertMany(e.altState.AppendNumbers(req.Name)...)
			}
			if e.Config.FlipWords {
				newNames.InsertMany(e.altState.FlipWords(req.Name)...)
			}
			if e.Config.AddWords {
				newNames.InsertMany(e.altState.AddSuffixWord(req.Name)...)
				newNames.InsertMany(e.altState.AddPrefixWord(req.Name)...)
			}
			if e.Config.EditDistance > 0 {
				newNames.InsertMany(e.altState.FuzzyLabelSearches(req.Name)...)
			}

			for _, name := range newNames.Slice() {
				if !e.Config.IsDomainInScope(name) {
					continue
				}

				e.newNameEvent(&requests.DNSRequest{
					Name:   name,
					Domain: req.Domain,
					Tag:    requests.ALT,
					Source: "Alterations",
				})
			}
		}
	}
}
