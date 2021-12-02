// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/datasrcs"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/netmap"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	"github.com/caffix/service"
	"github.com/caffix/stringset"
)

const (
	maxDNSPipelineTasks    int = 7500
	maxStorePipelineTasks  int = 50
	maxActivePipelineTasks int = 25
)

// Enumeration is the object type used to execute a DNS enumeration.
type Enumeration struct {
	Config      *config.Config
	Bus         *eventbus.EventBus
	Sys         systems.System
	Graph       *netmap.Graph
	closedOnce  sync.Once
	logQueue    queue.Queue
	ctx         context.Context
	srcs        []service.Service
	done        chan struct{}
	doneOnce    sync.Once
	crawlFilter *stringset.Set
	nameSrc     *enumSource
	subTask     *subdomainTask
	dnsTask     *dNSTask
	store       *dataManager
}

// NewEnumeration returns an initialized Enumeration that has not been started yet.
func NewEnumeration(cfg *config.Config, sys systems.System) *Enumeration {
	e := &Enumeration{
		Config:      cfg,
		Sys:         sys,
		Bus:         eventbus.NewEventBus(),
		Graph:       netmap.NewGraph(netmap.NewCayleyGraphMemory()),
		srcs:        datasrcs.SelectedDataSources(cfg, sys.DataSources()),
		logQueue:    queue.NewQueue(),
		done:        make(chan struct{}),
		crawlFilter: stringset.New(),
	}

	if cfg.Passive {
		return e
	}

	e.dnsTask = newDNSTask(e)
	e.subTask = newSubdomainTask(e)
	e.store = newDataManager(e)
	return e
}

// Close cleans up resources instantiated by the Enumeration.
func (e *Enumeration) Close() {
	e.closedOnce.Do(func() {
		e.Bus.Stop()
		e.Graph.Close()
		e.crawlFilter.Close()
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
	e.setupContext(ctx)

	// The pipeline input source will receive all the names
	e.nameSrc = newEnumSource(e)
	e.startupAndCleanup()
	defer e.stop()

	var stages []pipeline.Stage
	if !e.Config.Passive {
		stages = append(stages, pipeline.FIFO("", e.dnsTask.blacklistTaskFunc()))
		stages = append(stages, pipeline.FIFO("root", e.dnsTask.rootTaskFunc()))
		stages = append(stages, pipeline.DynamicPool("dns", e.dnsTask, e.min()))
	}

	stages = append(stages, pipeline.FIFO("filter", e.filterTaskFunc()))
	if !e.Config.Passive {
		stages = append(stages, pipeline.FixedPool("store", e.store, maxStorePipelineTasks))
		stages = append(stages, pipeline.FIFO("", e.subTask))
	}
	if e.Config.Active {
		activetask := newActiveTask(e, maxActivePipelineTasks)
		defer activetask.Stop()

		stages = append(stages, pipeline.FIFO("active", activetask))
	}
	/*
	 * Now that the pipeline input source has been setup, names provided
	 * by the user and names acquired from the graph database can be brought
	 * into the enumeration
	 */
	var wg sync.WaitGroup
	wg.Add(4)
	go e.submitKnownNames(&wg)
	go e.submitProvidedNames(&wg)
	go e.submitDomainNames(&wg)
	go e.submitASNs(&wg)
	wg.Wait()

	var err error
	if p := pipeline.NewPipeline(stages...); e.Config.Passive {
		err = p.Execute(e.ctx, e.nameSrc, e.makeOutputSink())
	} else {
		err = p.ExecuteBuffered(e.ctx, e.nameSrc, e.makeOutputSink(), 50)
		// Ensure all data has been stored
		e.store.signalDone <- struct{}{}
		<-e.store.confirmDone
	}
	return err
}

func (e *Enumeration) min() int {
	num := e.Config.MaxDNSQueries
	if num > maxDNSPipelineTasks {
		return maxDNSPipelineTasks
	}
	if num < 1 {
		return 1
	}
	return num
}

func (e *Enumeration) startupAndCleanup() {
	/*
	 * These events are important to the engine in order to receive data,
	 * logs, and notices about discoveries made during the enumeration
	 */
	e.Bus.Subscribe(requests.NewNameTopic, e.nameSrc.dataSourceName)
	e.Bus.Subscribe(requests.LogTopic, e.queueLog)
	if !e.Config.Passive {
		e.Bus.Subscribe(requests.NewAddrTopic, e.nameSrc.dataSourceAddr)
		e.Bus.Subscribe(requests.NewASNTopic, e.Sys.Cache().Update)
	}

	go e.periodicLogging()
	go func() {
		<-e.done
		e.Bus.Unsubscribe(requests.NewNameTopic, e.nameSrc.dataSourceName)
		e.Bus.Unsubscribe(requests.LogTopic, e.queueLog)

		if !e.Config.Passive {
			e.Bus.Unsubscribe(requests.NewAddrTopic, e.nameSrc.dataSourceAddr)
			e.Bus.Unsubscribe(requests.NewASNTopic, e.Sys.Cache().Update)
			e.nameSrc.Stop()
			e.subTask.Stop()
		}
		e.writeLogs(true)
	}()
}

// This context, used throughout the enumeration, will provide the ability to cancel operations
// and to pass the configuration and event bus to all the components.
func (e *Enumeration) setupContext(ctx context.Context) {
	newctx, cancel := context.WithCancel(ctx)

	// Monitor for termination of the enumeration
	go func() {
		<-e.done
		cancel()
	}()

	newctx = context.WithValue(newctx, requests.ContextConfig, e.Config)
	newctx = context.WithValue(newctx, requests.ContextEventBus, e.Bus)
	e.ctx = newctx
}

// Release the root domain names to the input source and each data source.
func (e *Enumeration) submitDomainNames(wg *sync.WaitGroup) {
	defer wg.Done()

	for _, domain := range e.Config.Domains() {
		req := &requests.DNSRequest{
			Name:   domain,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		}

		e.nameSrc.dataSourceName(req)
		for _, src := range e.srcs {
			src.Request(e.ctx, req.Clone().(*requests.DNSRequest))
		}
	}
}

// If requests were made for specific ASNs, then those requests are
// sent to included data sources at this point.
func (e *Enumeration) submitASNs(wg *sync.WaitGroup) {
	defer wg.Done()

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
		if ok && req != nil && req.Name != "" && e.Config.IsDomainInScope(req.Name) {
			if _, err := e.Graph.UpsertFQDN(e.ctx, req.Name, req.Source, e.Config.UUID.String()); err != nil {
				e.Bus.Publish(requests.LogTopic, eventbus.PriorityHigh, err.Error())
			}
		}
		return nil
	})
}

func (e *Enumeration) filterTaskFunc() pipeline.TaskFunc {
	filter := stringset.New()

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

		if name != "" && !filter.Has(name) {
			filter.Insert(name)
			return data, nil
		}
		return nil, nil
	})
}

func (e *Enumeration) submitKnownNames(wg *sync.WaitGroup) {
	defer wg.Done()

	filter := stringset.New()
	defer filter.Close()

	srcTags := make(map[string]string)
	for _, src := range e.Sys.DataSources() {
		srcTags[src.String()] = src.Description()
	}

	for _, g := range e.Sys.GraphDatabases() {
		e.readNamesFromDatabase(e.ctx, g, filter, srcTags)
	}
}

func (e *Enumeration) readNamesFromDatabase(ctx context.Context, g *netmap.Graph, filter *stringset.Set, stags map[string]string) {
	db := netmap.NewGraph(netmap.NewCayleyGraphMemory())
	if db == nil {
		return
	}
	defer db.Close()

	// Migrate the data into an in-memory graph database
	domains := e.Config.Domains()
	if err := g.MigrateEventsInScope(ctx, db, domains); err != nil {
		return
	}

	for _, event := range db.EventsInScope(ctx, domains...) {
		for _, name := range db.EventFQDNs(ctx, event) {
			select {
			case <-e.done:
				return
			default:
			}

			if filter.Has(name) {
				continue
			}
			filter.Insert(name)

			domain := e.Config.WhichDomain(name)
			if domain == "" {
				continue
			}
			if srcs, err := db.NodeSources(ctx, netmap.Node(name), event); err == nil {
				src := srcs[0]
				tag := stags[src]

				e.nameSrc.dataSourceName(&requests.DNSRequest{
					Name:   name,
					Domain: domain,
					Tag:    tag,
					Source: src,
				})
			}
		}
	}
}

func (e *Enumeration) submitProvidedNames(wg *sync.WaitGroup) {
	defer wg.Done()

	for _, name := range e.Config.ProvidedNames {
		if domain := e.Config.WhichDomain(name); domain != "" {
			e.nameSrc.dataSourceName(&requests.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    requests.EXTERNAL,
				Source: "User Input",
			})
		}
	}
}

func (e *Enumeration) queueLog(msg string) {
	e.logQueue.Append(msg)
}

func (e *Enumeration) writeLogs(all bool) {
	num := e.logQueue.Len() / 10
	if num <= 1000 {
		num = 1000
	}

	for i := 0; ; i++ {
		msg, ok := e.logQueue.Next()
		if !ok {
			break
		}

		if e.Config.Log != nil {
			e.Config.Log.Print(msg.(string))
		}

		if !all && i >= num {
			break
		}
	}
}

func (e *Enumeration) periodicLogging() {
	t := time.NewTimer(5 * time.Second)

	for {
		select {
		case <-e.done:
			return
		case <-t.C:
			e.writeLogs(false)
			t.Reset(5 * time.Second)
		}
	}
}
