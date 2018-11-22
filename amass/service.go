// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"errors"
	"time"
)

// Possible values for the AmassService.APIKeyRequired field.
const (
	APIKeyRequired int = iota
	APIKeyNotRequired
	APIkeyOptional
)

// AmassService is the object type for a service running within the Amass enumeration architecture.
type AmassService interface {
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

	SendRequest(req *AmassRequest)
	RequestChan() <-chan *AmassRequest

	IsActive() bool
	SetActive()

	// Returns channels that fire during Pause/Resume operations
	PauseChan() <-chan struct{}
	ResumeChan() <-chan struct{}

	// Returns a channel that is closed when the service is stopped
	Quit() <-chan struct{}

	// String description of the service
	String() string

	// Enum returns the Enumeration this service is supporting
	Enum() *Enumeration
}

// BaseAmassService provides common mechanisms to all Amass services in the enumeration architecture.
// It is used to compose a type that completely meets the AmassService interface.
type BaseAmassService struct {
	name      string
	started   bool
	stopped   bool
	active    time.Time
	setactive chan time.Time
	isactive  chan chan time.Time
	queue     chan *AmassRequest
	pause     chan struct{}
	resume    chan struct{}
	quit      chan struct{}

	// The specific service embedding BaseAmassService
	service AmassService
	// The enumeration that this service is supporting
	enumeration *Enumeration
}

// NewBaseAmassService returns an initialized BaseAmassService object.
func NewBaseAmassService(e *Enumeration, n string, srv AmassService) *BaseAmassService {
	max := e.Config.Timing.ToMaxFlow() + e.Config.Timing.ToReleasesPerSecond()

	return &BaseAmassService{
		name:        n,
		active:      time.Now(),
		setactive:   make(chan time.Time, max),
		isactive:    make(chan chan time.Time, max),
		queue:       make(chan *AmassRequest, max),
		pause:       make(chan struct{}, 10),
		resume:      make(chan struct{}, 10),
		quit:        make(chan struct{}),
		service:     srv,
		enumeration: e,
	}
}

// Start calls the OnStart method implemented for the AmassService.
func (bas *BaseAmassService) Start() error {
	if bas.started {
		return errors.New(bas.name + " has already been started")
	} else if bas.stopped {
		return errors.New(bas.name + " has been stopped")
	}
	bas.started = true
	go bas.processActivity()
	return bas.service.OnStart()
}

// OnStart is a placeholder that should be implemented by an AmassService
// that has code to execute during service start.
func (bas *BaseAmassService) OnStart() error {
	return nil
}

// Pause implements the AmassService interface
func (bas *BaseAmassService) Pause() error {
	err := bas.service.OnPause()

	go func() {
		bas.pause <- struct{}{}
	}()
	return err
}

// OnPause implements the AmassService interface
func (bas *BaseAmassService) OnPause() error {
	return nil
}

// Resume implements the AmassService interface
func (bas *BaseAmassService) Resume() error {
	err := bas.service.OnResume()

	go func() {
		bas.resume <- struct{}{}
	}()
	return err
}

// OnResume implements the AmassService interface
func (bas *BaseAmassService) OnResume() error {
	return nil
}

// Stop calls the OnStop method implemented for the AmassService.
func (bas *BaseAmassService) Stop() error {
	if bas.stopped {
		return errors.New(bas.name + " has already been stopped")
	}
	bas.Resume()
	err := bas.service.OnStop()
	bas.stopped = true
	close(bas.quit)
	return err
}

// OnStop is a placeholder that should be implemented by an AmassService
// that has code to execute during service stop.
func (bas *BaseAmassService) OnStop() error {
	return nil
}

// SendRequest adds the request provided by the parameter to the service request channel.
func (bas *BaseAmassService) SendRequest(req *AmassRequest) {
	bas.queue <- req
}

// RequestChan returns the channel that provides new service requests.
func (bas *BaseAmassService) RequestChan() <-chan *AmassRequest {
	return bas.queue
}

// IsActive returns true if SetActive has been called for the service within the last 10 seconds.
func (bas *BaseAmassService) IsActive() bool {
	a := make(chan time.Time)

	bas.isactive <- a
	if time.Now().Sub(<-a) > 10*time.Second {
		return false
	}
	return true
}

// SetActive marks the service as being active at time.Now() for future checks performed by the IsActive method.
func (bas *BaseAmassService) SetActive() {
	bas.setactive <- time.Now()
}

func (bas *BaseAmassService) processActivity() {
	for {
		select {
		case <-bas.Quit():
			return
		case ch := <-bas.isactive:
			ch <- bas.active
		case t := <-bas.setactive:
			if t.After(bas.active) {
				bas.active = t
			}
		}
	}
}

// PauseChan returns the pause channel for the service.
func (bas *BaseAmassService) PauseChan() <-chan struct{} {
	return bas.pause
}

// ResumeChan returns the resume channel for the service.
func (bas *BaseAmassService) ResumeChan() <-chan struct{} {
	return bas.resume
}

// Quit return the quit channel for the service.
func (bas *BaseAmassService) Quit() <-chan struct{} {
	return bas.quit
}

// String returns the name of the service.
func (bas *BaseAmassService) String() string {
	return bas.name
}

// Enum returns the Enumeration this service is supporting.
func (bas *BaseAmassService) Enum() *Enumeration {
	return bas.enumeration
}
