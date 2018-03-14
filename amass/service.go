// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"errors"
	"net"
	"sync"
)

// AmassRequest - Contains data obtained throughout AmassService processing
type AmassRequest struct {
	// The subdomain name
	Name string

	// The base domain that the name belongs to
	Domain string

	// The IP address that the name resolves to
	Address string

	// The netblock that the address belongs to
	Netblock *net.IPNet

	// The ASN that the address belongs to
	ASN int

	// The name of the service provider associated with the ASN
	ISP string

	// The type of data source that discovered the name
	Tag string

	// The exact data source that discovered the name
	Source string
}

type AmassService interface {
	// Start the service
	Start() error
	OnStart() error

	// Stop the service
	Stop() error
	OnStop() error

	// Returns the input channel for the service
	Input() <-chan *AmassRequest

	// Returns the output channel for the service
	Output() chan<- *AmassRequest

	// The request is sent non-blocking on the output chanel
	SendOut(req *AmassRequest)

	// Return true if the service is active
	IsActive() bool

	// Returns a channel that is closed when the service is stopped
	Quit() <-chan struct{}

	// String description of the service
	String() string
}

type BaseAmassService struct {
	sync.Mutex
	name    string
	started bool
	stopped bool
	input   <-chan *AmassRequest
	output  chan<- *AmassRequest
	active  bool
	quit    chan struct{}

	// The configuration being used by the service
	config *AmassConfig

	// The specific service embedding BaseAmassService
	service AmassService
}

func NewBaseAmassService(name string, config *AmassConfig, service AmassService) *BaseAmassService {
	return &BaseAmassService{
		name:    name,
		quit:    make(chan struct{}),
		config:  config,
		service: service,
	}
}

func (bas *BaseAmassService) Start() error {
	if bas.IsStarted() {
		return errors.New(bas.name + " service has already been started")
	} else if bas.IsStopped() {
		return errors.New(bas.name + " service has been stopped")
	}
	return bas.service.OnStart()
}

func (bas *BaseAmassService) OnStart() error {
	return nil
}

func (bas *BaseAmassService) Stop() error {
	if bas.IsStopped() {
		return errors.New(bas.name + " service has already been stopped")
	}
	err := bas.service.OnStop()
	close(bas.quit)
	return err
}

func (bas *BaseAmassService) OnStop() error {
	return nil
}

func (bas *BaseAmassService) Input() <-chan *AmassRequest {
	return bas.input
}

func (bas *BaseAmassService) Output() chan<- *AmassRequest {
	return bas.output
}

func (bas *BaseAmassService) SendOut(req *AmassRequest) {
	// Perform the channel write in a goroutine
	go func() {
		bas.output <- req
	}()
}

func (bas *BaseAmassService) IsActive() bool {
	bas.Lock()
	defer bas.Unlock()

	return bas.active
}

func (bas *BaseAmassService) SetActive(active bool) {
	bas.Lock()
	defer bas.Unlock()

	bas.active = active
}

func (bas *BaseAmassService) Quit() <-chan struct{} {
	return bas.quit
}

func (bas *BaseAmassService) String() string {
	return bas.name
}

func (bas *BaseAmassService) IsStarted() bool {
	bas.Lock()
	defer bas.Unlock()

	return bas.started
}

func (bas *BaseAmassService) SetStarted() {
	bas.Lock()
	defer bas.Unlock()

	bas.started = true
}

func (bas *BaseAmassService) IsStopped() bool {
	bas.Lock()
	defer bas.Unlock()

	return bas.stopped
}

func (bas *BaseAmassService) SetStopped() {
	bas.Lock()
	defer bas.Unlock()

	bas.stopped = true
}

func (bas *BaseAmassService) Config() *AmassConfig {
	return bas.config
}
