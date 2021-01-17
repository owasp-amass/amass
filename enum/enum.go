// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"sync"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/datasrcs"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/OWASP/Amass/v3/stringfilter"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
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
	source := newEnumSource(e, max)
	e.nameSrc = source
	e.Bus.Subscribe(requests.NewNameTopic, source.InputName)
	defer e.Bus.Unsubscribe(requests.NewNameTopic, source.InputName)
	sink := e.makeOutputSink()

	var stages []pipeline.Stage
	if !e.Config.Passive {
		// Task that performs initial filtering for new FQDNs and IP addresses
		stages = append(stages, pipeline.FixedPool("new",
			e.makeNewDataTaskFunc(newFQDNFilter(e), newAddressTask(e)), 50))
		stages = append(stages, pipeline.FIFO("", e.dnsTask.makeBlacklistTaskFunc()))
		// Task that performs DNS queries for root domain names
		stages = append(stages, pipeline.FixedPool("root", e.dnsTask.makeRootTaskFunc(), 100))
		// Add the dynamic pool of DNS resolution tasks
		stages = append(stages, pipeline.DynamicPool("dns", e.dnsTask, max))
	}

	stages = append(stages, pipeline.FIFO("filter", e.makeFilterTaskFunc()))

	if !e.Config.Passive {
		stages = append(stages, pipeline.FIFO("store", newDataManager(e)))
		stages = append(stages, pipeline.FixedPool("", e.subTask, 10))
	}
	if e.Config.Active {
		stages = append(stages, pipeline.FixedPool("active", newActiveTask(e), 10))
	}

	/*
	 * These events are important to the engine in order to receive data,
	 * logs, and notices about discoveries made during the enumeration
	 */
	e.Bus.Subscribe(requests.LogTopic, e.queueLog)
	defer e.Bus.Unsubscribe(requests.LogTopic, e.queueLog)
	if !e.Config.Passive {
		e.Bus.Subscribe(requests.NewAddrTopic, source.InputAddress)
		defer e.Bus.Unsubscribe(requests.NewAddrTopic, source.InputAddress)
		e.Bus.Subscribe(requests.NewASNTopic, e.Sys.Cache().Update)
		defer e.Bus.Unsubscribe(requests.NewASNTopic, e.Sys.Cache().Update)
	}

	/*
	 * Now that the pipeline input source has been setup, names provided
	 * by the user and names acquired from the graph database can be brought
	 * into the enumeration
	 */
	e.submitKnownNames()
	e.submitProvidedNames()

	/*
	 * This context, used throughout the enumeration, will provide the
	 * ability to cancel operations and to pass the configuration and
	 * event bus to all the components. If a timeout was provided in
	 * the configuration, it will go off that many minutes from this
	 * point in the enumeration process and terminate the pipeline
	 */
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
	defer e.stop()

	go e.periodicLogging()
	defer e.writeLogs(true)

	if !e.Config.Passive {
		// Attempt to fix IP address nodes without edges to netblocks
		defer e.Graph.HealAddressNodes(e.Sys.Cache(), e.Config.UUID.String())
	}

	// Release the root domain names to the input source and each data source
	for _, domain := range e.Config.Domains() {
		req := &requests.DNSRequest{
			Name:   domain,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		}

		source.InputName(req)
		for _, src := range e.srcs {
			src.Request(ctx, req.Clone().(*requests.DNSRequest))
		}
	}

	// If requests were made for specific ASNs, then those requests are
	// sent to included data sources at this point
	for _, asn := range e.Config.ASNs {
		req := &requests.ASNRequest{ASN: asn}

		for _, src := range e.srcs {
			src.Request(ctx, req.Clone().(*requests.ASNRequest))
		}
	}

	return pipeline.NewPipeline(stages...).Execute(ctx, source, sink)
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

		var err error
		if e.Config.IsDomainInScope(req.Name) {
			_, err = e.Graph.InsertFQDN(req.Name, req.Source, req.Tag, e.Config.UUID.String())
		}
		return err
	})
}

func (e *Enumeration) makeNewDataTaskFunc(fqdn *fqdnFilter, addrs *addrTask) pipeline.TaskFunc {
	return pipeline.TaskFunc(func(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
		select {
		case <-ctx.Done():
			return nil, nil
		default:
		}

		switch data.(type) {
		case *requests.DNSRequest:
			return fqdn.Process(ctx, data, tp)
		case *requests.AddrRequest:
			return addrs.Process(ctx, data, tp)
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

		if d, ok := data.(*requests.DNSRequest); ok && (d == nil || !d.Valid() || e.resolvedFilter.Duplicate(d.Name)) {
			return nil, nil
		}
		return data, nil
	})
}
