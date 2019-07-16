// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"errors"
	"io/ioutil"
	"log"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/core"
	eb "github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/handlers"
	"github.com/OWASP/Amass/amass/sources"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/google/uuid"
)

// Enumeration is the object type used to execute a DNS enumeration with Amass.
type Enumeration struct {
	Config *core.Config

	Bus *eb.EventBus

	// Link graph that collects all the information gathered by the enumeration
	Graph handlers.DataHandler

	// Names already known prior to the enumeration
	ProvidedNames []string

	// The channel that will receive the results
	Output chan *core.Output

	// Broadcast channel that indicates no further writes to the output channel
	Done chan struct{}

	dataSources []core.Service
	bruteSrv    core.Service

	// Pause/Resume channels for halting the enumeration
	pause  chan struct{}
	resume chan struct{}

	filter      *utils.StringFilter
	outputQueue *utils.Queue

	metricsLock       sync.RWMutex
	dnsQueriesPerSec  int
	dnsNamesRemaining int

	domainIdx int
}

// NewEnumeration returns an initialized Enumeration that has not been started yet.
func NewEnumeration() *Enumeration {
	e := &Enumeration{
		Config: &core.Config{
			UUID:           uuid.New(),
			Log:            log.New(ioutil.Discard, "", 0),
			Alterations:    true,
			FlipWords:      true,
			FlipNumbers:    true,
			AddWords:       true,
			AddNumbers:     true,
			MinForWordFlip: 2,
			EditDistance:   1,
			Recursive:      true,
		},
		Bus:         eb.NewEventBus(),
		Output:      make(chan *core.Output, 100),
		Done:        make(chan struct{}, 2),
		pause:       make(chan struct{}, 2),
		resume:      make(chan struct{}, 2),
		filter:      utils.NewStringFilter(),
		outputQueue: utils.NewQueue(),
	}
	e.dataSources = sources.GetAllSources(e.Config, e.Bus)
	return e
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

	// Setup the correct graph database handler
	err := e.setupGraph()
	if err != nil {
		return err
	}
	defer e.Graph.Close()

	e.Bus.Subscribe(core.OutputTopic, e.sendOutput)
	defer e.Bus.Unsubscribe(core.OutputTopic, e.sendOutput)

	// Select the data sources desired by the user
	if len(e.Config.DisabledDataSources) > 0 {
		e.dataSources = e.Config.ExcludeDisabledDataSources(e.dataSources)
	}

	// Add all the data sources that successfully start to the list
	var sources []core.Service
	for _, src := range e.dataSources {
		if err := src.Start(); err != nil {
			src.Stop()
			continue
		}
		sources = append(sources, src)
		defer src.Stop()
	}
	e.dataSources = sources
	// Select the correct services to be used in this enumeration
	services := e.requiredServices()
	for _, srv := range services {
		if err := srv.Start(); err != nil {
			return err
		}
		defer srv.Stop()
	}
	services = append(services, e.dataSources...)

	// Use all previously discovered names that are in scope
	go e.submitKnownNames()
	go e.submitProvidedNames()

	// Start with the first domain name provided in the configuration
	e.releaseDomainName()

	// The enumeration will not terminate until all output has been processed
	var wg sync.WaitGroup
	wg.Add(2)
	go e.checkForOutput(&wg)
	go e.processOutput(&wg)

	t := time.NewTicker(2 * time.Second)
	logTick := time.NewTicker(time.Minute)
loop:
	for {
		select {
		case <-e.Done:
			break loop
		case <-e.PauseChan():
			t.Stop()
		case <-e.ResumeChan():
			t = time.NewTicker(time.Second)
		case <-logTick.C:
			if !e.Config.Passive {
				e.Config.Log.Printf("Average DNS queries performed: %d/sec, DNS names remaining: %d",
					e.DNSQueriesPerSec(), e.DNSNamesRemaining())
			}
		case <-t.C:
			e.periodicChecks(services)
		}
	}
	t.Stop()
	logTick.Stop()
	wg.Wait()
	return nil
}

func (e *Enumeration) periodicChecks(services []core.Service) {
	done := true
	for _, srv := range services {
		if srv.IsActive() {
			done = false
			break
		}
	}
	if done {
		close(e.Done)
		return
	}

	if !e.Config.Passive {
		e.processMetrics(services)
		psec := e.DNSQueriesPerSec()
		// Check if it's too soon to release the next domain name
		if psec > 0 && ((e.DNSNamesRemaining()*len(InitialQueryTypes))/psec) > 10 {
			return
		}
		// Let the services know that the enumeration is ready for more names
		for _, srv := range services {
			go srv.LowNumberOfNames()
		}
	}
	// Attempt to send the next domain to data sources/brute forcing
	e.releaseDomainName()
}

func (e *Enumeration) releaseDomainName() {
	domains := e.Config.Domains()

	if e.domainIdx >= len(domains) {
		return
	}

	for _, srv := range append(e.dataSources, e.bruteSrv) {
		if srv == nil {
			continue
		}

		srv.SendDNSRequest(&core.DNSRequest{
			Name:   domains[e.domainIdx],
			Domain: domains[e.domainIdx],
		})
	}
	e.domainIdx++
}

func (e *Enumeration) submitKnownNames() {
	for _, enum := range e.Graph.EnumerationList() {
		var found bool

		for _, domain := range e.Graph.EnumerationDomains(enum) {
			if e.Config.IsDomainInScope(domain) {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		for _, o := range e.Graph.GetOutput(enum, true) {
			if e.Config.IsDomainInScope(o.Name) {
				e.Bus.Publish(core.NewNameTopic, &core.DNSRequest{
					Name:   o.Name,
					Domain: o.Domain,
					Tag:    o.Tag,
					Source: o.Source,
				})
			}
		}
	}
}

func (e *Enumeration) submitProvidedNames() {
	for _, name := range e.ProvidedNames {
		if domain := e.Config.WhichDomain(name); domain != "" {
			e.Bus.Publish(core.NewNameTopic, &core.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    core.EXTERNAL,
				Source: "User Input",
			})
		}
	}
}

// Select the correct services to be used in this enumeration.
func (e *Enumeration) requiredServices() []core.Service {
	var services []core.Service

	if !e.Config.Passive {
		dms := NewDataManagerService(e.Config, e.Bus)
		dms.AddDataHandler(e.Graph)
		if e.Config.DataOptsWriter != nil {
			dms.AddDataHandler(handlers.NewDataOptsHandler(e.Config.DataOptsWriter))
		}
		services = append(services, NewDNSService(e.Config, e.Bus),
			dms, NewActiveCertService(e.Config, e.Bus))
	}

	namesrv := NewNameService(e.Config, e.Bus)
	namesrv.RegisterGraph(e.Graph)
	services = append(services, namesrv, NewAddressService(e.Config, e.Bus))

	if !e.Config.Passive {
		e.bruteSrv = NewBruteForceService(e.Config, e.Bus)
		services = append(services, e.bruteSrv,
			NewMarkovService(e.Config, e.Bus), NewAlterationService(e.Config, e.Bus))
	}
	return services
}

// Select the graph that will store the enumeration findings.
func (e *Enumeration) setupGraph() error {
	if e.Config.GremlinURL != "" {
		gremlin := handlers.NewGremlin(e.Config.GremlinURL,
			e.Config.GremlinUser, e.Config.GremlinPass, e.Config.Log)
		e.Graph = gremlin
		return nil
	}

	graph := handlers.NewGraph(e.Config.Dir)
	if graph == nil {
		return errors.New("Failed to create the graph")
	}
	e.Graph = graph
	return nil
}

// DNSQueriesPerSec returns the number of DNS queries the enumeration has performed per second.
func (e *Enumeration) DNSQueriesPerSec() int {
	e.metricsLock.RLock()
	defer e.metricsLock.RUnlock()

	return e.dnsQueriesPerSec
}

// DNSNamesRemaining returns the number of discovered DNS names yet to be handled by the enumeration.
func (e *Enumeration) DNSNamesRemaining() int {
	e.metricsLock.RLock()
	defer e.metricsLock.RUnlock()

	return e.dnsNamesRemaining
}

func (e *Enumeration) processMetrics(services []core.Service) {
	var total, remaining int
	for _, srv := range services {
		stats := srv.Stats()

		remaining += stats.NamesRemaining
		total += stats.DNSQueriesPerSec
	}

	e.metricsLock.Lock()
	e.dnsQueriesPerSec = total
	e.dnsNamesRemaining = remaining
	e.metricsLock.Unlock()
}

func (e *Enumeration) processOutput(wg *sync.WaitGroup) {
	defer wg.Done()

	curIdx := 0
	maxIdx := 7
	delays := []int{250, 500, 750, 1000, 1250, 1500, 1750, 2000}
loop:
	for {
		select {
		case <-e.Done:
			break loop
		default:
			element, ok := e.outputQueue.Next()
			if !ok {
				if curIdx < maxIdx {
					curIdx++
				}
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				continue
			}
			curIdx = 0
			output := element.(*core.Output)
			if !e.filter.Duplicate(output.Name) {
				e.Output <- output
			}
		}
	}
	time.Sleep(5 * time.Second)
	// Handle all remaining elements on the queue
	for {
		element, ok := e.outputQueue.Next()
		if !ok {
			break
		}
		output := element.(*core.Output)
		if !e.filter.Duplicate(output.Name) {
			e.Output <- output
		}
	}
	close(e.Output)
}

func (e *Enumeration) checkForOutput(wg *sync.WaitGroup) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	defer wg.Done()

	for {
		select {
		case <-e.Done:
			// Handle all remaining pieces of output
			e.queueNewGraphEntries(e.Config.UUID.String(), time.Millisecond)
			return
		case <-t.C:
			e.queueNewGraphEntries(e.Config.UUID.String(), 3*time.Second)
		}
	}
}

func (e *Enumeration) queueNewGraphEntries(uuid string, delay time.Duration) {
	for _, o := range e.Graph.GetOutput(uuid, false) {
		if time.Now().Add(delay).After(o.Timestamp) {
			e.Graph.MarkAsRead(&handlers.DataOptsParams{
				UUID:   uuid,
				Name:   o.Name,
				Domain: o.Domain,
			})

			if e.Config.IsDomainInScope(o.Name) {
				e.outputQueue.Append(o)
			}
		}
	}
}

func (e *Enumeration) sendOutput(o *core.Output) {
	select {
	case <-e.Done:
		return
	default:
		if e.Config.IsDomainInScope(o.Name) {
			e.outputQueue.Append(o)
		}
	}
}

// Pause temporarily halts the enumeration.
func (e *Enumeration) Pause() {
	e.pause <- struct{}{}
}

// PauseChan returns the channel that is signaled when Pause is called.
func (e *Enumeration) PauseChan() <-chan struct{} {
	return e.pause
}

// Resume causes a previously paused enumeration to resume execution.
func (e *Enumeration) Resume() {
	e.resume <- struct{}{}
}

// ResumeChan returns the channel that is signaled when Resume is called.
func (e *Enumeration) ResumeChan() <-chan struct{} {
	return e.resume
}

// GetAllSourceNames returns the names of all the available data sources.
func (e *Enumeration) GetAllSourceNames() []string {
	var names []string

	for _, source := range e.dataSources {
		names = append(names, source.String())
	}
	return names
}
