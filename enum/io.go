// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

func (e *Enumeration) submitKnownNames(wg *sync.WaitGroup) {
	defer wg.Done()

	for _, g := range e.Sys.GraphDatabases() {
		for _, enum := range g.EnumerationList() {
			var found bool

			for _, domain := range g.EnumerationDomains(enum) {
				if e.Config.IsDomainInScope(domain) {
					found = true
					break
				}
			}
			if !found {
				continue
			}

			for _, o := range g.GetOutput(enum, true) {
				if e.Config.IsDomainInScope(o.Name) {
					e.Bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
						Name:   o.Name,
						Domain: o.Domain,
						Tag:    requests.EXTERNAL,
						Source: "Previous Enum",
					})
				}
			}
		}
	}
}

func (e *Enumeration) submitProvidedNames(wg *sync.WaitGroup) {
	defer wg.Done()

	for _, name := range e.Config.ProvidedNames {
		if domain := e.Config.WhichDomain(name); domain != "" {
			e.Bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    requests.EXTERNAL,
				Source: "User Input",
			})
		}
	}
}

func (e *Enumeration) namesFromCertificates(addr string) {
	for _, name := range http.PullCertificateNames(addr, e.Config.Ports) {
		if n := strings.TrimSpace(name); n != "" {
			if domain := e.Config.WhichDomain(n); domain != "" {
				e.Bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
					Name:   n,
					Domain: domain,
					Tag:    requests.CERT,
					Source: "Active Cert",
				})
			}
		}
	}
}

func (e *Enumeration) processOutput(wg *sync.WaitGroup) {
	defer wg.Done()
	curIdx := 0
	maxIdx := 7
	delays := []int{250, 500, 750, 1000, 1250, 1500, 1750, 2000}
loop:
	for {
		select {
		case <-e.done:
			break loop
		default:
			element, ok := e.outputQueue.Next()
			if !ok {
				if curIdx < maxIdx {
					curIdx++
				}
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				continue loop
			}
			curIdx = 0
			output := element.(*requests.Output)
			e.filters.OutputLock.Lock()

			if e.filters.Output.Has(output.Name) == false {
				e.filters.Output.Insert(output.Name)
				e.Output <- output
				e.filters.OutputLock.Unlock()
			} else {
				e.filters.OutputLock.Unlock()
				continue
			}

		}
	}
	time.Sleep(5 * time.Second)
	// Handle all remaining elements on the queue
	for {
		element, ok := e.outputQueue.Next()
		if !ok {
			break
		}
		output := element.(*requests.Output)
		e.filters.OutputLock.Lock()

		if e.filters.Output.Has(output.Name) == false {
			e.filters.Output.Insert(output.Name)
			e.Output <- output
			e.filters.OutputLock.Unlock()
		} else {
			e.filters.OutputLock.Unlock()
			continue
		}

	}
	close(e.Output)
}

func (e *Enumeration) checkForOutput(wg *sync.WaitGroup) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	defer wg.Done()

	for {
		select {
		case <-e.done:
			// Handle all remaining pieces of output
			e.queueNewGraphEntries(e.Config.UUID.String(), time.Millisecond)
			return
		case <-t.C:
			e.queueNewGraphEntries(e.Config.UUID.String(), 3*time.Second)
		}
	}
}

func (e *Enumeration) queueNewGraphEntries(uuid string, delay time.Duration) {
	for _, g := range e.Sys.GraphDatabases() {
		for _, o := range g.GetOutput(uuid, false) {
			if time.Now().After(o.Timestamp.Add(delay)) {
				g.MarkAsRead(&graph.DataOptsParams{
					UUID:   uuid,
					Name:   o.Name,
					Domain: o.Domain,
				})

				if e.Config.IsDomainInScope(o.Name) {
					e.outputQueue.Append(o)
				}
			}
		}
	}
}

func (e *Enumeration) sendOutput(o *requests.Output) {
	select {
	case <-e.done:
		return
	default:
		if e.Config.IsDomainInScope(o.Name) {
			e.outputQueue.Append(o)
		}
	}
}

func (e *Enumeration) queueLog(msg string) {
	e.logQueue.Append(msg)
}

func (e *Enumeration) writeLogs() {
	for {
		msg, ok := e.logQueue.Next()
		if !ok {
			break
		}

		if e.Config.Log != nil {
			e.Config.Log.Print(msg.(string))
		}
	}
}
