// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"errors"
	"sync"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/queue"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
)

const (
	// ServiceRequestChanLength is the length of the chan that pulls requests off the queue.
	ServiceRequestChanLength int = 1000
)

// Possible values for the AmassService.APIKeyRequired field.
const (
	APIKeyRequired int = iota
	APIKeyNotRequired
	APIkeyOptional
)

// ServiceStats provides metrics from an Amass service.
type ServiceStats struct {
	DNSQueriesPerSec int
	NamesRemaining   int
	AddrsRemaining   int
}

// Service is the object type for a service running within the Amass enumeration architecture.
type Service interface {
	// Start the service
	Start() error
	OnStart() error

	// Pause the service
	Pause() error
	OnPause() error

	// Resume the service
	Resume() error
	OnResume() error

	// Stop the service
	Stop() error
	OnStop() error

	// Architecture is ready for more names
	LowNumberOfNames() error
	OnLowNumberOfNames() error

	// Methods to support processing of DNSRequests
	SendDNSRequest(req *requests.DNSRequest)
	DNSRequestChan() <-chan *requests.DNSRequest
	DNSRequestLen() int

	// Methods to support processing of AddrRequests
	SendAddrRequest(req *requests.AddrRequest)
	AddrRequestChan() <-chan *requests.AddrRequest
	AddrRequestLen() int

	// Methods to support processing of ASNRequests
	SendASNRequest(req *requests.ASNRequest)
	ASNRequestChan() <-chan *requests.ASNRequest
	ASNRequestLen() int

	// Methods to support processing of WhoisRequests
	SendWhoisRequest(req *requests.WhoisRequest)
	WhoisRequestChan() <-chan *requests.WhoisRequest
	WhoisRequestLen() int

	IsActive() bool
	SetActive()

	// Returns channels that fire during Pause/Resume operations
	PauseChan() <-chan struct{}
	ResumeChan() <-chan struct{}

	// Returns a channel that is closed when the service is stopped
	Quit() <-chan struct{}

	// String description of the service
	String() string

	// Returns the configuration for the enumeration this service supports
	Config() *config.Config

	// Returns the event bus that handles communication
	Bus() *eb.EventBus

	// Returns the resolver pool that handles DNS requests
	Pool() *resolvers.ResolverPool

	// Returns current ServiceStats that provide performance metrics
	Stats() *ServiceStats
}

// BaseService provides common mechanisms to all Amass services in the enumeration architecture.
// It is used to compose a type that completely meets the AmassService interface.
type BaseService struct {
	name          string
	started       bool
	stopped       bool
	activeLock    sync.Mutex
	active        time.Time
	dnsQueue      *queue.Queue
	dnsRequests   chan *requests.DNSRequest
	addrQueue     *queue.Queue
	addrRequests  chan *requests.AddrRequest
	asnQueue      *queue.Queue
	asnRequests   chan *requests.ASNRequest
	whoisQueue    *queue.Queue
	whoisRequests chan *requests.WhoisRequest
	pause         chan struct{}
	resume        chan struct{}
	quit          chan struct{}

	// The specific service embedding BaseAmassService
	service Service

	// The configuration for this service
	cfg *config.Config

	// The event bus that handles message passing
	bus *eb.EventBus

	// The resolver pool used for DNS requests
	pool *resolvers.ResolverPool
}

// NewBaseService returns an initialized BaseService object.
func NewBaseService(srv Service, name string, cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *BaseService {
	return &BaseService{
		name:          name,
		active:        time.Now(),
		dnsQueue:      new(queue.Queue),
		dnsRequests:   make(chan *requests.DNSRequest, ServiceRequestChanLength),
		addrQueue:     new(queue.Queue),
		addrRequests:  make(chan *requests.AddrRequest, ServiceRequestChanLength),
		asnQueue:      new(queue.Queue),
		asnRequests:   make(chan *requests.ASNRequest, ServiceRequestChanLength),
		whoisQueue:    new(queue.Queue),
		whoisRequests: make(chan *requests.WhoisRequest, ServiceRequestChanLength),
		pause:         make(chan struct{}, 10),
		resume:        make(chan struct{}, 10),
		quit:          make(chan struct{}),
		service:       srv,
		cfg:           cfg,
		bus:           bus,
		pool:          pool,
	}
}

// Start calls the OnStart method implemented for the Service.
func (bas *BaseService) Start() error {
	if bas.started {
		return errors.New(bas.name + " has already been started")
	} else if bas.stopped {
		return errors.New(bas.name + " has been stopped")
	}
	bas.started = true
	go bas.processDNSRequests()
	go bas.processAddrRequests()
	go bas.processASNRequests()
	go bas.processWhoisRequests()
	return bas.service.OnStart()
}

// OnStart is a placeholder that should be implemented by an Service
// that has code to execute during service start.
func (bas *BaseService) OnStart() error {
	return nil
}

// Pause implements the Service interface
func (bas *BaseService) Pause() error {
	err := bas.service.OnPause()

	go func() {
		bas.pause <- struct{}{}
	}()
	return err
}

// OnPause implements the Service interface
func (bas *BaseService) OnPause() error {
	return nil
}

// Resume implements the Service interface
func (bas *BaseService) Resume() error {
	err := bas.service.OnResume()

	go func() {
		bas.resume <- struct{}{}
	}()
	return err
}

// OnResume implements the Service interface
func (bas *BaseService) OnResume() error {
	return nil
}

// Stop calls the OnStop method implemented for the Service.
func (bas *BaseService) Stop() error {
	if bas.stopped {
		return errors.New(bas.name + " has already been stopped")
	}
	bas.Resume()
	err := bas.service.OnStop()
	bas.stopped = true
	close(bas.quit)
	return err
}

// OnStop is a placeholder that should be implemented by a Service
// that has code to execute during service stop.
func (bas *BaseService) OnStop() error {
	return nil
}

// LowNumberOfNames calls the OnLowNumberOfNames method implemented for the Service.
func (bas *BaseService) LowNumberOfNames() error {
	err := bas.service.OnLowNumberOfNames()

	return err
}

// OnLowNumberOfNames is a placeholder that should be implemented by a Service
// that has code to be executed when the enumeration is low in names to resolve.
func (bas *BaseService) OnLowNumberOfNames() error {
	return nil
}

// SendDNSRequest adds the request provided by the parameter to the service request channel.
func (bas *BaseService) SendDNSRequest(req *requests.DNSRequest) {
	bas.dnsQueue.Append(req)
}

// DNSRequestChan returns the channel that provides new service requests.
func (bas *BaseService) DNSRequestChan() <-chan *requests.DNSRequest {
	return bas.dnsRequests
}

func (bas *BaseService) processDNSRequests() {
	curIdx := 0
	maxIdx := 7
	delays := []int{25, 50, 75, 100, 150, 250, 500, 750}

	for {
		select {
		case <-bas.Quit():
			return
		default:
			element, ok := bas.dnsQueue.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue
			}
			curIdx = 0
			bas.dnsRequests <- element.(*requests.DNSRequest)
		}
	}
}

// DNSRequestLen returns the current length of the request queue.
func (bas *BaseService) DNSRequestLen() int {
	return bas.dnsQueue.Len()
}

// SendAddrRequest adds the request provided by the parameter to the service request channel.
func (bas *BaseService) SendAddrRequest(req *requests.AddrRequest) {
	bas.addrQueue.Append(req)
}

// AddrRequestChan returns the channel that provides new service requests.
func (bas *BaseService) AddrRequestChan() <-chan *requests.AddrRequest {
	return bas.addrRequests
}

func (bas *BaseService) processAddrRequests() {
	curIdx := 0
	maxIdx := 7
	delays := []int{25, 50, 75, 100, 150, 250, 500, 750}

	for {
		select {
		case <-bas.Quit():
			return
		default:
			element, ok := bas.addrQueue.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue
			}
			curIdx = 0
			bas.addrRequests <- element.(*requests.AddrRequest)
		}
	}
}

// AddrRequestLen returns the current length of the request queue.
func (bas *BaseService) AddrRequestLen() int {
	return bas.addrQueue.Len()
}

// SendASNRequest adds the request provided by the parameter to the service request channel.
func (bas *BaseService) SendASNRequest(req *requests.ASNRequest) {
	bas.asnQueue.Append(req)
}

// ASNRequestChan returns the channel that provides new service requests.
func (bas *BaseService) ASNRequestChan() <-chan *requests.ASNRequest {
	return bas.asnRequests
}

func (bas *BaseService) processASNRequests() {
	curIdx := 0
	maxIdx := 7
	delays := []int{25, 50, 75, 100, 150, 250, 500, 750}

	for {
		select {
		case <-bas.Quit():
			return
		default:
			element, ok := bas.asnQueue.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue
			}
			curIdx = 0
			bas.asnRequests <- element.(*requests.ASNRequest)
		}
	}
}

// ASNRequestLen returns the current length of the request queue.
func (bas *BaseService) ASNRequestLen() int {
	return bas.asnQueue.Len()
}

// SendWhoisRequest adds the request provided by the parameter to the service request channel.
func (bas *BaseService) SendWhoisRequest(req *requests.WhoisRequest) {
	bas.whoisQueue.Append(req)
}

// WhoisRequestChan returns the channel that provides new service requests.
func (bas *BaseService) WhoisRequestChan() <-chan *requests.WhoisRequest {
	return bas.whoisRequests
}

func (bas *BaseService) processWhoisRequests() {
	curIdx := 0
	maxIdx := 7
	delays := []int{25, 50, 75, 100, 150, 250, 500, 750}

	for {
		select {
		case <-bas.Quit():
			return
		default:
			element, ok := bas.whoisQueue.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue
			}
			curIdx = 0
			bas.whoisRequests <- element.(*requests.WhoisRequest)
		}
	}
}

// WhoisRequestLen returns the current length of the request queue.
func (bas *BaseService) WhoisRequestLen() int {
	return bas.whoisQueue.Len()
}

// IsActive returns true if SetActive has been called for the service within the last 10 seconds.
func (bas *BaseService) IsActive() bool {
	bas.activeLock.Lock()
	defer bas.activeLock.Unlock()

	if time.Now().Sub(bas.active) > 10*time.Second {
		return false
	}
	return true
}

// SetActive marks the service as being active at time.Now() for future checks performed by the IsActive method.
func (bas *BaseService) SetActive() {
	bas.activeLock.Lock()
	defer bas.activeLock.Unlock()

	bas.active = time.Now()
}

// PauseChan returns the pause channel for the service.
func (bas *BaseService) PauseChan() <-chan struct{} {
	return bas.pause
}

// ResumeChan returns the resume channel for the service.
func (bas *BaseService) ResumeChan() <-chan struct{} {
	return bas.resume
}

// Quit return the quit channel for the service.
func (bas *BaseService) Quit() <-chan struct{} {
	return bas.quit
}

// String returns the name of the service.
func (bas *BaseService) String() string {
	return bas.name
}

// Config returns the Config for the enumeration this service supports.
func (bas *BaseService) Config() *config.Config {
	return bas.cfg
}

// Bus returns the EventBus that handles communication for the service.
func (bas *BaseService) Bus() *eb.EventBus {
	return bas.bus
}

// Pool returns the ResolverPool that handles DNS requests for the service.
func (bas *BaseService) Pool() *resolvers.ResolverPool {
	return bas.pool
}

// Stats returns current ServiceStats that provide performance metrics
func (bas *BaseService) Stats() *ServiceStats {
	return new(ServiceStats)
}
