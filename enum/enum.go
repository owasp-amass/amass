// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"sync"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/datasrcs"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringfilter"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	"github.com/caffix/resolvers"
	"github.com/caffix/service"
)

var filterMaxSize int64 = 1 << 23

// Enumeration is the object type used to execute a DNS enumeration.
type Enumeration struct {
	Config         *config.Config
	Bus            *eventbus.EventBus
	Sys            systems.System
	Graph          *graph.Graph
	closedOnce     sync.Once
	logQueue       queue.Queue
	ctx            context.Context
	srcs           []service.Service
	done           chan struct{}
	doneOnce       sync.Once
	resolvedFilter stringfilter.Filter
	crawlFilter    stringfilter.Filter
	nameSrc        *enumSource
	subTask        *subdomainTask
	dnsTask        *dNSTask
}

// NewEnumeration returns an initialized Enumeration that has not been started yet.
func NewEnumeration(cfg *config.Config, sys systems.System) *Enumeration {
	e := &Enumeration{
		Config:         cfg,
		Sys:            sys,
		Bus:            eventbus.NewEventBus(),
		Graph:          graph.NewGraph(graph.NewCayleyGraphMemory()),
		srcs:           datasrcs.SelectedDataSources(cfg, sys.DataSources()),
		logQueue:       queue.NewQueue(),
		done:           make(chan struct{}),
		resolvedFilter: stringfilter.NewBloomFilter(filterMaxSize),
		crawlFilter:    stringfilter.NewStringFilter(),
	}

	if cfg.Passive {
		return e
	}

	e.dnsTask = newDNSTask(e)
	e.subTask = newSubdomainTask(e)
	return e
}

// Close cleans up resources instantiated by the Enumeration.
func (e *Enumeration) Close() {
	e.closedOnce.Do(func() {
		e.Bus.Stop()
		e.Graph.Close()
	})
}

func (e *Enumeration) stop() {
	e.doneOnce.Do(func() {
		close(e.done)
	})
}

// Start begins the vertical domain correlation process.
func (e *Enumeration) Start(ctx context.Context) error {
	if err := e.Config.CheckSettings(); err != nil {
		return err
	}

	max := e.Config.MaxDNSQueries * int(resolvers.QueryTimeout.Seconds())
	// The pipeline input source will receive all the names
	e.nameSrc = newEnumSource(e, max)
	e.startupAndCleanup(ctx)

	var stages []pipeline.Stage
	if !e.Config.Passive {
		// Task that performs initial filtering for new FQDNs and IP addresses
		stages = append(stages, pipeline.FixedPool("new",
			e.makeNewDataTaskFunc(newFQDNFilter(e), newAddressTask(e)), 50))
		stages = append(stages, pipeline.FixedPool("", e.dnsTask.makeBlacklistTaskFunc(), 50))
		// Task that performs DNS queries for root domain names
		stages = append(stages, pipeline.DynamicPool("root", e.dnsTask.makeRootTaskFunc(), max))
		// Add the dynamic pool of DNS resolution tasks
		stages = append(stages, pipeline.DynamicPool("dns", e.dnsTask, max))
	}

	stages = append(stages, pipeline.FIFO("filter", e.makeFilterTaskFunc()))

	if !e.Config.Passive {
		stages = append(stages, pipeline.FIFO("store", newDataManager(e)))
		stages = append(stages, pipeline.FIFO("", e.subTask))
	}
	if e.Config.Active {
		stages = append(stages, pipeline.FIFO("active", newActiveTask(e, 50)))
	}

	/*
	 * Now that the pipeline input source has been setup, names provided
	 * by the user and names acquired from the graph database can be brought
	 * into the enumeration
	 */
	e.submitKnownNames()
	e.submitProvidedNames()
	e.submitDomainNames()
	e.submitASNs()

	return pipeline.NewPipeline(stages...).Execute(e.ctx, e.nameSrc, e.makeOutputSink())
}

func (e *Enumeration) startupAndCleanup(ctx context.Context) {
	/*
	 * These events are important to the engine in order to receive data,
	 * logs, and notices about discoveries made during the enumeration
	 */
	e.Bus.Subscribe(requests.NewNameTopic, e.nameSrc.InputName)
	e.Bus.Subscribe(requests.LogTopic, e.queueLog)
	if !e.Config.Passive {
		e.Bus.Subscribe(requests.NewAddrTopic, e.nameSrc.InputAddress)
		e.Bus.Subscribe(requests.NewASNTopic, e.Sys.Cache().Update)
	}

	e.setupContext(ctx)
	go e.periodicLogging()

	go func() {
		<-e.done
		defer e.Bus.Unsubscribe(requests.NewNameTopic, e.nameSrc.InputName)
		defer e.Bus.Unsubscribe(requests.LogTopic, e.queueLog)

		if !e.Config.Passive {
			defer e.Bus.Unsubscribe(requests.NewAddrTopic, e.nameSrc.InputAddress)
			defer e.Bus.Unsubscribe(requests.NewASNTopic, e.Sys.Cache().Update)
			// Attempt to fix IP address nodes without edges to netblocks
			defer func() { _ = e.Graph.HealAddressNodes(e.Sys.Cache(), e.Config.UUID.String()) }()
		}

		defer e.stop()
		defer e.writeLogs(true)
	}()
}

// This context, used throughout the enumeration, will provide the ability to cancel operations
// and to pass the configuration and event bus to all the components. If a timeout was provided
// in the configuration, it will go off that many minutes from this point in the enumeration
// process and terminate the pipeline.
func (e *Enumeration) setupContext(ctx context.Context) context.Context {
	var cancel context.CancelFunc

	ctx, cancel = context.WithCancel(ctx)
	ctx = context.WithValue(ctx, requests.ContextConfig, e.Config)
	ctx = context.WithValue(ctx, requests.ContextEventBus, e.Bus)
	e.ctx = ctx

	// Monitor for termination of the enumeration
	go func() {
		<-e.done
		cancel()
	}()

	return ctx
}

// Release the root domain names to the input source and each data source.
func (e *Enumeration) submitDomainNames() {
	for _, domain := range e.Config.Domains() {
		req := &requests.DNSRequest{
			Name:   domain,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		}

		e.nameSrc.InputName(req)
		for _, src := range e.srcs {
			src.Request(e.ctx, req.Clone().(*requests.DNSRequest))
		}
	}
}

// If requests were made for specific ASNs, then those requests are
// sent to included data sources at this point.
func (e *Enumeration) submitASNs() {
	for _, asn := range e.Config.ASNs {
		req := &requests.ASNRequest{ASN: asn}

		for _, src := range e.srcs {
			src.Request(e.ctx, req.Clone().(*requests.ASNRequest))
		}
	}
}

func (e *Enumeration) makeOutputSink() pipeline.SinkFunc {
	return pipeline.SinkFunc(func(ctx context.Context, data pipeline.Data) error {
		if !e.Config.Passive {
			return nil
		}

		req, ok := data.(*requests.DNSRequest)
		if !ok || req == nil || req.Name == "" {
			return nil
		}

		if e.Config.IsDomainInScope(req.Name) {
			if _, err := e.Graph.InsertFQDN(req.Name, req.Source, req.Tag, e.Config.UUID.String()); err != nil {
				e.Bus.Publish(requests.LogTopic, eventbus.PriorityHigh, err.Error())
			}
		}
		return nil
	})
}

func (e *Enumeration) makeNewDataTaskFunc(fqdn *fqdnFilter, addrs *addrTask) pipeline.TaskFunc {
	return pipeline.TaskFunc(func(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
		select {
		case <-ctx.Done():
			return nil, nil
		default:
		}

		switch v := data.(type) {
		case *requests.DNSRequest:
			if v != nil && v.Valid() {
				return fqdn.Process(ctx, data, tp)
			}
			return nil, nil
		case *requests.AddrRequest:
			if v != nil && v.Valid() {
				return addrs.Process(ctx, data, tp)
			}
			return nil, nil
		}
		return data, nil
	})
}

func (e *Enumeration) makeFilterTaskFunc() pipeline.TaskFunc {
	return pipeline.TaskFunc(func(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
		select {
		case <-ctx.Done():
			return nil, nil
		default:
		}

		var name string
		switch v := data.(type) {
		case *requests.DNSRequest:
			if v != nil && v.Valid() {
				name = v.Name
			}
		case *requests.AddrRequest:
			if v != nil && v.Valid() {
				name = v.Address
			}
		default:
			return data, nil
		}

		if name != "" && !e.resolvedFilter.Duplicate(name) {
			return data, nil
		}
		return nil, nil
	})
}
