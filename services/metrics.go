// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"time"

	"github.com/OWASP/Amass/queue"
)

// MetricsCollector provides Amass services with the ability to track performance.
type MetricsCollector struct {
	// The Amass Service collecting the performance metrics
	service Service

	// The function that will provide the number of DNS names remaining
	namesRemaining func() int

	// The channel that handles requests for ServiceStats
	statsReq chan chan *ServiceStats

	// The queue that holds DNS query event times
	queries *queue.Queue

	// The channel that signals the metrics collector to halt execution
	done chan struct{}
}

// NewMetricsCollector returns an initialized MetricsCollector.
func NewMetricsCollector(srv Service) *MetricsCollector {
	mc := &MetricsCollector{
		service:  srv,
		statsReq: make(chan chan *ServiceStats, 10),
		queries:  new(queue.Queue),
		done:     make(chan struct{}, 2),
	}
	go mc.processMetrics()
	return mc
}

// Stop halts execution of the metrics collector.
func (mc *MetricsCollector) Stop() {
	close(mc.done)
}

// NamesRemainingCallback updates the names remaining callback routine.
func (mc *MetricsCollector) NamesRemainingCallback(nrc func() int) {
	mc.namesRemaining = nrc
}

// Stats returns ServiceStats for the metrics collected by this MetricsCollector.
func (mc *MetricsCollector) Stats() *ServiceStats {
	c := make(chan *ServiceStats)

	mc.statsReq <- c
	return <-c
}

func (mc *MetricsCollector) processMetrics() {
	var perSec []int

	last := time.Now()
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		select {
		case <-mc.done:
			return
		case <-t.C:
			perSec = append(perSec, mc.eventsPerSec(last, mc.queries))
			perSec = trimMetricSlice(perSec)
			last = time.Now()
		case c := <-mc.statsReq:
			var remaining int
			if mc.namesRemaining != nil {
				remaining = mc.namesRemaining()
			}
			c <- &ServiceStats{
				DNSQueriesPerSec: metricSliceAverage(perSec),
				NamesRemaining:   remaining,
			}
		}
	}
}

// QueryTime allows a DNS query event time to be posted with the MetricsCollector.
func (mc *MetricsCollector) QueryTime(t time.Time) {
	mc.queries.Append(t)
}

func (mc *MetricsCollector) eventsPerSec(last time.Time, q *queue.Queue) int {
	var num int
	for {
		element, ok := q.Next()
		if !ok {
			break
		}
		comTime := element.(time.Time)
		if comTime.After(last) {
			num++
		}
	}
	return num
}

func metricSliceAverage(m []int) int {
	var total int
	num := len(m)
	if num < 10 {
		return 0
	}
	for _, s := range m {
		total += s
	}
	return total / num
}

func trimMetricSlice(m []int) []int {
	s := len(m)
	if s <= 60 {
		return m
	}
	idx := s - 60
	return m[idx:]
}
