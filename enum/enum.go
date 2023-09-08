// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"context"
	"sync"
	"time"

	"github.com/caffix/netmap"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	"github.com/caffix/service"
	"github.com/owasp-amass/amass/v4/datasrcs"
	"github.com/owasp-amass/amass/v4/requests"
	"github.com/owasp-amass/amass/v4/systems"
	"github.com/owasp-amass/config/config"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
)

// Enumeration is the object type used to execute a DNS enumeration.
type Enumeration struct {
	Config   *config.Config
	Sys      systems.System
	ctx      context.Context
	graph    *netmap.Graph
	srcs     []service.Service
	done     chan struct{}
	nameSrc  *enumSource
	subTask  *subdomainTask
	dnsTask  *dnsTask
	valTask  *dnsTask
	store    *dataManager
	requests queue.Queue
	plock    sync.Mutex
	pending  bool
}

// NewEnumeration returns an initialized Enumeration that has not been started yet.
func NewEnumeration(cfg *config.Config, sys systems.System, graph *netmap.Graph) *Enumeration {
	return &Enumeration{
		Config:   cfg,
		Sys:      sys,
		graph:    graph,
		srcs:     datasrcs.SelectedDataSources(cfg, sys.DataSources()),
		requests: queue.NewQueue(),
	}
}

// Start begins the vertical domain correlation process.
func (e *Enumeration) Start(ctx context.Context) error {
	e.done = make(chan struct{})
	defer close(e.done)

	if err := e.Config.CheckSettings(); err != nil {
		return err
	}
	// This context, used throughout the enumeration, will provide the
	// ability to pass the configuration and event bus to all the components
	var cancel context.CancelFunc
	e.ctx, cancel = context.WithCancel(ctx)
	defer cancel()
	go e.manageDataSrcRequests()

	e.dnsTask = newDNSTask(e, false)
	e.valTask = newDNSTask(e, true)
	e.store = newDataManager(e)
	e.subTask = newSubdomainTask(e)
	defer e.subTask.Stop()
	defer e.dnsTask.stop()
	defer e.valTask.stop()

	var stages []pipeline.Stage
	stages = append(stages, pipeline.FIFO("root", e.valTask.rootTaskFunc()))
	stages = append(stages, pipeline.FIFO("dns", e.dnsTask))
	stages = append(stages, pipeline.FIFO("validate", e.valTask))
	stages = append(stages, pipeline.FIFO("store", e.store))
	stages = append(stages, pipeline.FIFO("", e.subTask))

	p := pipeline.NewPipeline(stages...)
	// The pipeline input source will receive all the names
	e.nameSrc = newEnumSource(p, e)
	defer e.nameSrc.Stop()

	e.submitASNs()
	e.submitDomainNames()
	/*
	 * Now that the pipeline input source has been setup, names provided
	 * by the user and names acquired from the graph database can be brought
	 * into the enumeration
	 */
	go e.submitKnownNames()
	go e.submitProvidedNames()

	err := p.ExecuteBuffered(e.ctx, e.nameSrc, e.makeOutputSink(), 50)
	// Ensure all data has been stored
	<-e.store.Stop()
	return err
}

// Release the root domain names to the input source and each data source.
func (e *Enumeration) submitDomainNames() {
	for _, domain := range e.Config.Domains() {
		req := &requests.DNSRequest{
			Name:   domain,
			Domain: domain,
		}

		e.nameSrc.newName(req)
		e.sendRequests(req.Clone().(*requests.DNSRequest))
	}
}

// If requests were made for specific ASNs, then those requests are
// sent to included data sources at this point.
func (e *Enumeration) submitASNs() {
	for _, asn := range e.Config.Scope.ASNs {
		e.sendRequests(&requests.ASNRequest{ASN: asn})
	}
}

func (e *Enumeration) sendRequests(element interface{}) {
	e.requests.Append(element)
}

func (e *Enumeration) manageDataSrcRequests() {
	nameToSrc := make(map[string]service.Service)
	for _, src := range e.srcs {
		nameToSrc[src.String()] = src
	}

	pending := make(map[string]bool)
	for _, src := range e.srcs {
		pending[src.String()] = false
	}

	finished := make(chan string, len(e.srcs)*2)
	requestsMap := make(map[string][]interface{})
loop:
	for {
		select {
		case <-e.done:
			break loop
		case <-e.ctx.Done():
			break loop
		case <-e.requests.Signal():
			element, ok := e.requests.Next()
			if !ok {
				continue loop
			}

			for name := range nameToSrc {
				if src := nameToSrc[name]; src != nil && src.HandlesReq(element) {
					if len(requestsMap[name]) == 0 && !pending[name] {
						go e.fireRequest(src, element, finished)
						pending[name] = true
					} else {
						requestsMap[name] = append(requestsMap[name], element)
					}
				}
			}
		case name := <-finished:
			if len(requestsMap[name]) == 0 {
				pending[name] = false
				e.setRequestsPending(pending)
				continue loop
			}

			go e.fireRequest(nameToSrc[name], requestsMap[name][0], finished)
			requestsMap[name] = requestsMap[name][1:]
		}
	}
	e.requests.Process(func(e interface{}) {})
}

func (e *Enumeration) requestsPending() bool {
	e.plock.Lock()
	defer e.plock.Unlock()

	return e.pending
}

func (e *Enumeration) setRequestsPending(p map[string]bool) {
	var pending bool

	for _, b := range p {
		if b {
			pending = true
			break
		}
	}

	e.plock.Lock()
	e.pending = pending
	e.plock.Unlock()
}

func (e *Enumeration) fireRequest(srv service.Service, req interface{}, finished chan string) {
	select {
	case <-e.done:
	case <-e.ctx.Done():
	case <-srv.Done():
	case srv.Input() <- req:
	}
	finished <- srv.String()
}

func (e *Enumeration) makeOutputSink() pipeline.SinkFunc {
	return pipeline.SinkFunc(func(ctx context.Context, data pipeline.Data) error {
		return nil
	})
}

func (e *Enumeration) submitKnownNames() {
	for _, g := range e.Sys.GraphDatabases() {
		e.readNamesFromDatabase(g)
	}
}

func (e *Enumeration) readNamesFromDatabase(db *netmap.Graph) {
	for _, d := range e.Config.Domains() {
		assets, err := db.DB.FindByScope([]oam.Asset{domain.FQDN{Name: d}}, time.Time{})
		if err != nil {
			continue
		}

		for _, a := range assets {
			if fqdn, ok := a.Asset.(domain.FQDN); ok {
				select {
				case <-e.done:
					return
				default:
				}

				domain := e.Config.WhichDomain(fqdn.Name)
				if domain == "" {
					continue
				}

				e.nameSrc.newName(&requests.DNSRequest{
					Name:   fqdn.Name,
					Domain: domain,
				})
			}
		}
	}
}

func (e *Enumeration) submitProvidedNames() {
	for _, name := range e.Config.ProvidedNames {
		select {
		case <-e.done:
			return
		default:
		}
		if domain := e.Config.WhichDomain(name); domain != "" {
			e.nameSrc.newName(&requests.DNSRequest{
				Name:   name,
				Domain: domain,
			})
		}
	}
}
