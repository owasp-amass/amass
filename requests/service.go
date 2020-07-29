// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package requests

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/OWASP/Amass/v3/queue"
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

// Service is the object type for a service running within the Amass architecture.
type Service interface {
	// Start the service
	Start() error
	OnStart() error

	// Stop the service
	Stop() error
	OnStop() error

	// RequestLen returns the current length of the request queue
	RequestLen() int

	// Methods to support processing of DNSRequests
	DNSRequest(ctx context.Context, req *DNSRequest)
	OnDNSRequest(ctx context.Context, req *DNSRequest)

	// Methods to support processing of resolved FQDNs
	Resolved(ctx context.Context, req *DNSRequest)
	OnResolved(ctx context.Context, req *DNSRequest)

	// Methods to support processing of discovered proper subdomains
	SubdomainDiscovered(ctx context.Context, req *DNSRequest, times int)
	OnSubdomainDiscovered(ctx context.Context, req *DNSRequest, times int)

	// Methods to support processing of AddrRequests
	AddrRequest(ctx context.Context, req *AddrRequest)
	OnAddrRequest(ctx context.Context, req *AddrRequest)

	// Methods to support processing of ASNRequests
	ASNRequest(ctx context.Context, req *ASNRequest)
	OnASNRequest(ctx context.Context, req *ASNRequest)

	// Methods to support processing of WhoisRequests
	WhoisRequest(ctx context.Context, req *WhoisRequest)
	OnWhoisRequest(ctx context.Context, req *WhoisRequest)

	// Returns a channel that is closed when the service is stopped
	Quit() <-chan struct{}

	// Type returns the type of the service
	Type() string

	// String description of the service
	String() string

	// Returns current ServiceStats that provide performance metrics
	Stats() *ServiceStats
}

// BaseService provides common mechanisms to all Amass services in the enumeration architecture.
// It is used to compose a type that completely meets the Service interface.
type BaseService struct {
	// The unique service name shared throughout the system
	name string

	// Indicates that the service has already been started
	started bool

	// Indicates that the service has already been stopped
	stopped bool

	// The queue for all incoming request types
	queue *queue.Queue

	// The broadcast channel closed when the service is stopped
	quit chan struct{}

	setRateChan   chan time.Duration
	checkRateChan chan chan struct{}
	clearRateChan chan struct{}

	// The specific service embedding BaseAmassService
	service Service
}

// NewBaseService returns an initialized BaseService object.
func NewBaseService(srv Service, name string) *BaseService {
	bas := &BaseService{
		name:          name,
		queue:         new(queue.Queue),
		quit:          make(chan struct{}),
		setRateChan:   make(chan time.Duration, 10),
		checkRateChan: make(chan chan struct{}, 10),
		clearRateChan: make(chan struct{}, 10),
		service:       srv,
	}

	go bas.manageRateLimit()
	return bas
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

// Stop calls the OnStop method implemented for the Service.
func (bas *BaseService) Stop() error {
	if bas.stopped {
		return errors.New(bas.name + " has already been stopped")
	}
	bas.stopped = true

	close(bas.quit)
	return nil
}

// OnStop is a placeholder that should be implemented by a Service
// that has code to execute during service stop.
func (bas *BaseService) OnStop() error {
	return nil
}

// Type returns the type of the service.
func (bas *BaseService) Type() string {
	return NONE
}

// RequestLen returns the current length of the request queue.
func (bas *BaseService) RequestLen() int {
	return bas.queue.Len()
}

// DNSRequest adds the request provided by the parameter to the service request channel.
func (bas *BaseService) DNSRequest(ctx context.Context, req *DNSRequest) {
	bas.queueRequest(bas.service.OnDNSRequest, ctx, req)
}

// OnDNSRequest is called for a request that was queued via DNSRequest.
func (bas *BaseService) OnDNSRequest(ctx context.Context, req *DNSRequest) {
	return
}

// Resolved adds the request provided by the parameter to the service request channel.
func (bas *BaseService) Resolved(ctx context.Context, req *DNSRequest) {
	bas.queueRequest(bas.service.OnResolved, ctx, req)
}

// OnResolved is called for a request that was queued via Resolved.
func (bas *BaseService) OnResolved(ctx context.Context, req *DNSRequest) {
	return
}

// SubdomainDiscovered adds the request provided by the parameter to the service request channel.
func (bas *BaseService) SubdomainDiscovered(ctx context.Context, req *DNSRequest, times int) {
	bas.queueRequest(bas.service.OnSubdomainDiscovered, ctx, req, times)
}

// OnSubdomainDiscovered is called for a request that was queued via DNSRequest.
func (bas *BaseService) OnSubdomainDiscovered(ctx context.Context, req *DNSRequest, times int) {
	return
}

// AddrRequest adds the request provided by the parameter to the service request channel.
func (bas *BaseService) AddrRequest(ctx context.Context, req *AddrRequest) {
	bas.queueRequest(bas.service.OnAddrRequest, ctx, req)
}

// OnAddrRequest is called for a request that was queued via AddrRequest.
func (bas *BaseService) OnAddrRequest(ctx context.Context, req *AddrRequest) {
	return
}

// ASNRequest adds the request provided by the parameter to the service request channel.
func (bas *BaseService) ASNRequest(ctx context.Context, req *ASNRequest) {
	bas.queueRequest(bas.service.OnASNRequest, ctx, req)
}

// OnASNRequest is called for a request that was queued via ASNRequest.
func (bas *BaseService) OnASNRequest(ctx context.Context, req *ASNRequest) {
	return
}

// WhoisRequest adds the request provided by the parameter to the service request channel.
func (bas *BaseService) WhoisRequest(ctx context.Context, req *WhoisRequest) {
	bas.queueRequest(bas.service.OnWhoisRequest, ctx, req)
}

// OnWhoisRequest is called for a request that was queued via WhoisRequest.
func (bas *BaseService) OnWhoisRequest(ctx context.Context, req *WhoisRequest) {
	return
}

// Quit return the quit channel for the service.
func (bas *BaseService) Quit() <-chan struct{} {
	return bas.quit
}

// String returns the name of the service.
func (bas *BaseService) String() string {
	return bas.name
}

// Stats returns current ServiceStats that provide performance metrics.
func (bas *BaseService) Stats() *ServiceStats {
	return new(ServiceStats)
}

// SetRateLimit sets the minimum wait between checks.
func (bas *BaseService) SetRateLimit(min time.Duration) {
	bas.setRateChan <- min
}

// CheckRateLimit blocks until the minimum wait since the last call.
func (bas *BaseService) CheckRateLimit() {
	ch := make(chan struct{}, 2)

	bas.checkRateChan <- ch
	<-ch
}

// ClearLast resets the last value so the service can be utilized immediately.
func (bas *BaseService) ClearLast() {
	bas.clearRateChan <- struct{}{}
}

func (bas *BaseService) manageRateLimit() {
	var rateLimit time.Duration
	last := time.Now().Truncate(10 * time.Minute)
loop:
	for {
		select {
		case <-bas.quit:
			return
		case d := <-bas.setRateChan:
			rateLimit = d
		case ch := <-bas.checkRateChan:
			if rateLimit == time.Duration(0) {
				ch <- struct{}{}
				continue loop
			}

			if delta := time.Now().Sub(last); rateLimit > delta {
				time.Sleep(rateLimit - delta)
			}
			last = time.Now()
			ch <- struct{}{}
		case <-bas.clearRateChan:
			last.Truncate(time.Hour)
		}
	}
}

type queuedCall struct {
	Func reflect.Value
	Args []reflect.Value
}

func (bas *BaseService) queueRequest(fn interface{}, args ...interface{}) {
	passedArgs := make([]reflect.Value, 0)
	for _, arg := range args {
		passedArgs = append(passedArgs, reflect.ValueOf(arg))
	}

	bas.queue.Append(&queuedCall{
		Func: reflect.ValueOf(fn),
		Args: passedArgs,
	})
}

func (bas *BaseService) processRequests() {
	curIdx := 0
	maxIdx := 6
	delays := []int{25, 50, 75, 100, 150, 250, 500}
loop:
	for {
		select {
		case <-bas.Quit():
			bas.service.OnStop()
			return
		default:
			element, ok := bas.queue.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue loop
			}
			curIdx = 0
			e := element.(*queuedCall)
			ctx := e.Args[0].Interface().(context.Context)

			select {
			case <-ctx.Done():
				continue loop
			default:
				// Call the queued function or method
				e.Func.Call(e.Args)
			}
		}
	}
}
