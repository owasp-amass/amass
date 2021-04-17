// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"time"

	"github.com/OWASP/Amass/v3/filter"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/netmap"
)

func (e *Enumeration) submitKnownNames() {
	filter := filter.NewStringFilter()
	srcTags := make(map[string]string)

	for _, src := range e.Sys.DataSources() {
		srcTags[src.String()] = src.Description()
	}

	for _, g := range e.Sys.GraphDatabases() {
		for _, event := range g.EventsInScope(e.Config.Domains()...) {
			for _, name := range g.EventFQDNs(event) {
				select {
				case <-e.done:
					return
				default:
				}

				if filter.Duplicate(name) {
					continue
				}

				if domain := e.Config.WhichDomain(name); domain != "" {
					if srcs, err := g.NodeSources(netmap.Node(name), event); err == nil {
						src := srcs[0]
						tag := srcTags[src]

						e.nameSrc.InputName(&requests.DNSRequest{
							Name:   name,
							Domain: domain,
							Tag:    tag,
							Source: src,
						})
					}
				}
			}
		}
	}
}

func (e *Enumeration) submitProvidedNames() {
	for _, name := range e.Config.ProvidedNames {
		if domain := e.Config.WhichDomain(name); domain != "" {
			e.nameSrc.InputName(&requests.DNSRequest{
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
