// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"errors"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/utils/dns"
)

// AmassRequest - Contains data obtained throughout AmassService processing
type AmassRequest struct {
	Name    string
	Domain  string
	Records []dns.DNSAnswer
	Tag     string
	Source  string
}

type AmassService interface {
	// Start the service
	Start() error
	OnStart() error

	// OPSEC for the service
	List() string

	// Stop the service
	Stop() error
	OnStop() error

	NextRequest() *AmassRequest
	SendRequest(req *AmassRequest)

	IsActive() bool
	SetActive()

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
	queue   []*AmassRequest
	active  time.Time
	quit    chan struct{}
	config  *AmassConfig

	// The specific service embedding BaseAmassService
	service AmassService
}

func NewBaseAmassService(name string, config *AmassConfig, service AmassService) *BaseAmassService {
	return &BaseAmassService{
		name:    name,
		queue:   make([]*AmassRequest, 0, 50),
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

func (bas *BaseAmassService) List() string {
	return "N/A"
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

func (bas *BaseAmassService) NextRequest() *AmassRequest {
	bas.Lock()
	defer bas.Unlock()

	if len(bas.queue) == 0 {
		return nil
	}

	var next *AmassRequest

	if len(bas.queue) > 0 {
		next = bas.queue[0]
		// Remove the first slice element
		if len(bas.queue) > 1 {
			bas.queue = bas.queue[1:]
		} else {
			bas.queue = []*AmassRequest{}
		}
	}
	return next
}

func (bas *BaseAmassService) SendRequest(req *AmassRequest) {
	bas.Lock()
	defer bas.Unlock()

	bas.queue = append(bas.queue, req)
}

func (bas *BaseAmassService) IsActive() bool {
	bas.Lock()
	defer bas.Unlock()

	if time.Now().Sub(bas.active) > 5*time.Second {
		return false
	}
	return true
}

func (bas *BaseAmassService) SetActive() {
	bas.Lock()
	defer bas.Unlock()

	bas.active = time.Now()
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
