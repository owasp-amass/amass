// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package core

import (
	"errors"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/utils"
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

	SendRequest(req *Request)
	RequestChan() <-chan *Request

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
	Config() *Config

	// Returns the event bus that handles communication for the enumeration
	Bus() *EventBus

	// Returns current ServiceStats that provide performance metrics
	Stats() *ServiceStats
}

// BaseService provides common mechanisms to all Amass services in the enumeration architecture.
// It is used to compose a type that completely meets the AmassService interface.
type BaseService struct {
	name       string
	started    bool
	stopped    bool
	activeLock sync.Mutex
	active     time.Time
	queue      *utils.Queue
	requests   chan *Request
	pause      chan struct{}
	resume     chan struct{}
	quit       chan struct{}

	// The specific service embedding BaseAmassService
	service Service

	// The global configuration for the enumeration this service supports
	config *Config

	// The event bus that handles message passing for the enumeration
	bus *EventBus
}

// NewBaseService returns an initialized BaseService object.
func NewBaseService(srv Service, name string, config *Config, bus *EventBus) *BaseService {
	return &BaseService{
		name:     name,
		active:   time.Now(),
		queue:    utils.NewQueue(),
		requests: make(chan *Request, 1000),
		pause:    make(chan struct{}, 10),
		resume:   make(chan struct{}, 10),
		quit:     make(chan struct{}),
		service:  srv,
		config:   config,
		bus:      bus,
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
	go bas.processRequests()
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

// OnStop is a placeholder that should be implemented by an Service
// that has code to execute during service stop.
func (bas *BaseService) OnStop() error {
	return nil
}

// SendRequest adds the request provided by the parameter to the service request channel.
func (bas *BaseService) SendRequest(req *Request) {
	bas.queue.Append(req)
}

// RequestChan returns the channel that provides new service requests.
func (bas *BaseService) RequestChan() <-chan *Request {
	return bas.requests
}

func (bas *BaseService) processRequests() {
	curIdx := 0
	maxIdx := 7
	delays := []int{25, 50, 75, 100, 150, 250, 500, 750}

	for {
		select {
		case <-bas.Quit():
			return
		default:
			element, ok := bas.queue.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue
			}
			curIdx = 0
			bas.requests <- element.(*Request)
		}
	}
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
func (bas *BaseService) Config() *Config {
	return bas.config
}

// Bus returns the EventBus that handles communication for the enumeration.
func (bas *BaseService) Bus() *EventBus {
	return bas.bus
}

// Stats returns current ServiceStats that provide performance metrics
func (bas *BaseService) Stats() *ServiceStats {
	return new(ServiceStats)
}
