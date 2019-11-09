// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"strings"
	"sync"

	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

func (e *Enumeration) submitKnownNames(wg *sync.WaitGroup) {
	defer wg.Done()

	for _, g := range e.Sys.GraphDatabases() {
		for _, enum := range g.EventList() {
			var found bool

			for _, domain := range g.EventDomains(enum) {
				if e.Config.IsDomainInScope(domain) {
					found = true
					break
				}
			}
			if !found {
				continue
			}

			for _, o := range g.GetOutput(enum) {
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

	<-e.done

	e.graphEntries(e.Config.UUID.String())
	for {
		element, ok := e.outputQueue.Next()
		if !ok {
			break
		}

		output := element.(*requests.Output)
		if !e.filters.Output.Duplicate(output.Name) {
			e.Output <- output
		}
	}

	close(e.Output)
}

func (e *Enumeration) graphEntries(uuid string) {
	for _, g := range e.Sys.GraphDatabases() {
		for _, o := range g.GetOutput(uuid) {
			e.updateLastActive("Output")

			if e.Config.IsDomainInScope(o.Name) {
				e.outputQueue.Append(o)
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
