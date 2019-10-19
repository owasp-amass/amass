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
	"github.com/OWASP/Amass/net/dns"
	"github.com/OWASP/Amass/queue"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/services"
	sf "github.com/OWASP/Amass/stringfilter"
	"github.com/OWASP/Amass/stringset"
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

	ctx context.Context

	filters *Filters
	dataMgr services.Service

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
		Config: config.NewConfig(),
		Bus:    eb.NewEventBus(),
		Sys:    sys,
		filters: &Filters{
			NewNames:      sf.NewStringFilter(),
			Resolved:      sf.NewStringFilter(),
			NewAddrs:      sf.NewStringFilter(),
			SweepAddrs:    sf.NewStringFilter(),
			Output:        sf.NewStringFilter(),
			PassiveOutput: sf.NewStringFilter(),
		},
		srcs:        stringset.New(),
		Output:      make(chan *requests.Output, 100),
		outputQueue: new(queue.Queue),
		logQueue:    new(queue.Queue),
		done:        make(chan struct{}, 2),
		netCache:    make(map[int]*requests.ASNRequest),
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
			if l := e.lastActive(); time.Now().Sub(l) > 5*time.Second {
				e.Done()
			}
		case <-logTick.C:
			if !e.Config.Passive {
				e.Config.Log.Printf("Average DNS queries performed: %d/sec, DNS names remaining: %d",
					e.DNSQueriesPerSec(), e.DNSNamesRemaining())

				e.clearPerSec()
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

func (e *Enumeration) setupEventBus() {
	e.Bus.Subscribe(requests.OutputTopic, e.sendOutput)
	e.Bus.Subscribe(requests.LogTopic, e.queueLog)
	e.Bus.Subscribe(requests.SetActiveTopic, e.updateLastActive)
	e.Bus.Subscribe(requests.ResolveCompleted, e.incQueriesPerSec)

	e.Bus.Subscribe(requests.NewNameTopic, e.newNameEvent)
	e.Bus.Subscribe(requests.NameResolvedTopic, e.newResolvedName)

	e.Bus.Subscribe(requests.NewAddrTopic, e.newAddress)
	e.Bus.Subscribe(requests.NewASNTopic, e.newASN)

	// Setup all core services to receive the appropriate events
	for _, srv := range e.Sys.CoreServices() {
		switch srv.String() {
		case "Data Manager":
			continue
		case "DNS Service":
			e.Bus.Subscribe(requests.ResolveNameTopic, srv.DNSRequest)
			e.Bus.Subscribe(requests.SubDiscoveredTopic, srv.SubdomainDiscovered)
		case "Brute Forcing":
			if e.Config.BruteForcing {
				e.Bus.Subscribe(requests.NameRequestTopic, srv.DNSRequest)

				if e.Config.Recursive && e.Config.MinForRecursive > 0 {
					e.Bus.Subscribe(requests.SubDiscoveredTopic, srv.SubdomainDiscovered)
				}
			}
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
	e.Bus.Unsubscribe(requests.NameResolvedTopic, e.newResolvedName)

	e.Bus.Unsubscribe(requests.NewAddrTopic, e.newAddress)
	e.Bus.Unsubscribe(requests.NewASNTopic, e.newASN)

	// Setup all core services to receive the appropriate events
	for _, srv := range e.Sys.CoreServices() {
		switch srv.String() {
		case "Data Manager":
			continue
		case "DNS Service":
			e.Bus.Unsubscribe(requests.ResolveNameTopic, srv.DNSRequest)
		case "Brute Forcing":
			if e.Config.BruteForcing {
				e.Bus.Unsubscribe(requests.NameRequestTopic, srv.DNSRequest)

				if e.Config.Recursive && e.Config.MinForRecursive > 0 {
					e.Bus.Unsubscribe(requests.SubDiscoveredTopic, srv.SubdomainDiscovered)
				}
			}
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

	e.updateLastActive("enum")

	req.Name = strings.ToLower(dns.RemoveAsteriskLabel(req.Name))
	req.Name = strings.Trim(req.Name, ".")
	req.Domain = strings.ToLower(req.Domain)

	// Filter on the DNS name + the value from TrustedTag
	if e.filters.NewNames.Duplicate(req.Name +
		strconv.FormatBool(requests.TrustedTag(req.Tag))) {
		return
	}

	if e.Config.Passive {
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
	req.Name = strings.ToLower(dns.RemoveAsteriskLabel(req.Name))
	req.Name = strings.Trim(req.Name, ".")
	req.Domain = strings.ToLower(req.Domain)

	e.updateLastActive("enum")

	if e.filters.Resolved.Duplicate(req.Name) {
		return
	}

	// Write the DNS name information to the graph databases
	e.dataMgr.DNSRequest(e.ctx, req)

	/*
	 * Do not go further if the name is not in scope
	 */
	if !e.Config.IsDomainInScope(req.Name) {
		return
	}

	// Keep track of all domains and proper subdomains discovered
	e.checkSubdomain(req)

	if e.Config.BruteForcing && e.Config.Recursive {
		for _, name := range topNames {
			e.Bus.Publish(requests.ResolveNameTopic, e.ctx, &requests.DNSRequest{
				Name:   name + "." + req.Name,
				Domain: req.Domain,
				Tag:    requests.BRUTE,
				Source: "Brute Forcing",
			})
		}
	}

	for _, srv := range e.Sys.CoreServices() {
		if e.Config.BruteForcing && e.Config.Recursive &&
			e.Config.MinForRecursive == 0 && srv.String() == "Brute Forcing" {
			srv.DNSRequest(e.ctx, req)
		}
	}

	// Update all name alteration objects
	if e.Config.Alterations {
		e.performNameAlterations(req.Name, req.Domain)
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

func (e *Enumeration) performNameAlterations(name, domain string) {
	if !e.Config.IsDomainInScope(name) ||
		(len(strings.Split(domain, ".")) == len(strings.Split(name, "."))) {
		return
	}

	newNames := stringset.New()

	e.markovModel.Train(name)
	if e.markovModel.TotalTrainings() >= 50 &&
		(e.markovModel.TotalTrainings()%10 == 0) {
		newNames.InsertMany(e.markovModel.GenerateNames(100)...)
	}

	if e.Config.FlipNumbers {
		newNames.InsertMany(e.altState.FlipNumbers(name)...)
	}
	if e.Config.AddNumbers {
		newNames.InsertMany(e.altState.AppendNumbers(name)...)
	}
	if e.Config.FlipWords {
		newNames.InsertMany(e.altState.FlipWords(name)...)
	}
	if e.Config.AddWords {
		newNames.InsertMany(e.altState.AddSuffixWord(name)...)
		newNames.InsertMany(e.altState.AddPrefixWord(name)...)
	}
	if e.Config.EditDistance > 0 {
		newNames.InsertMany(e.altState.FuzzyLabelSearches(name)...)
	}

	for _, n := range newNames.Slice() {
		if !e.Config.IsDomainInScope(n) {
			continue
		}

		e.newNameEvent(&requests.DNSRequest{
			Name:   n,
			Domain: domain,
			Tag:    requests.ALT,
			Source: "Alterations",
		})
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

	// Check if the subdomain should be added to the markov model
	if e.Config.Alterations && times == 1 {
		e.markovModel.AddSubdomain(sub)
	}

	e.srcsLock.Lock()
	defer e.srcsLock.Unlock()

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

	e.updateLastActive("enum")

	if e.filters.NewAddrs.Duplicate(req.Address) {
		return
	}

	if e.Config.Active {
		e.namesFromCertificates(req.Address)
	}

	e.investigateAddress(req)
}

func (e *Enumeration) investigateAddress(req *requests.AddrRequest) {
	asn := e.ipSearch(req.Address)
	if asn == nil {
		// Query the data sources for ASN information related to this IP address
		e.srcsLock.Lock()
		for _, src := range e.Sys.DataSources() {
			if e.srcs.Has(src.String()) {
				src.ASNRequest(e.ctx, &requests.ASNRequest{Address: req.Address})
			}
		}
		e.srcsLock.Unlock()

		// Wait until the ASN has been provided
		for {
			select {
			case <-e.done:
				return
			default:
				asn = e.ipSearch(req.Address)
				if asn == nil {
					time.Sleep(2 * time.Second)
				}
			}
		}

		if asn == nil {
			return
		}
	}

	// Write the ASN information to the graph databases
	e.dataMgr.ASNRequest(e.ctx, asn)

	// Perform the reverse DNS sweep if the IP address is in scope
	if e.Config.IsDomainInScope(req.Domain) {
		if _, cidr, _ := net.ParseCIDR(asn.Prefix); cidr != nil {
			e.reverseDNSSweep(req.Address, cidr)
		}
	}
}

func (e *Enumeration) newASN(req *requests.ASNRequest) {
	e.updateLastActive("enum")
	e.updateConfigWithNetblocks(req)
	e.updateASNCache(req)

	if req.Address != "" {
		if r := e.ipSearch(req.Address); r != nil {
			// Write the ASN information to the graph databases
			e.dataMgr.ASNRequest(e.ctx, r)
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
