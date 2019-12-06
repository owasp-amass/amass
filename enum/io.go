// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

func (e *Enumeration) submitKnownNames(wg *sync.WaitGroup) {
	defer wg.Done()

	var events []string

	fqdns := stringset.New()
	for _, g := range e.Sys.GraphDatabases() {
		for _, enum := range g.EventList() {
			for _, domain := range g.EventDomains(enum) {
				if e.Config.IsDomainInScope(domain) {
					events = append(events, enum)
				}
			}
		}

		for _, d := range g.EventSubdomains(events...) {
			if e.Config.IsDomainInScope(d) {
				fqdns.Insert(d)
			}
		}
	}

	for f := range fqdns {
		etld, err := publicsuffix.EffectiveTLDPlusOne(f)
		if err != nil {
			continue
		}

		e.Bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   f,
			Domain: etld,
			Tag:    requests.EXTERNAL,
			Source: "Previous Enum",
		})
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
	defer close(e.Output)
	defer wg.Done()

	curIdx := 0
	maxIdx := 6
	delays := []int{25, 50, 75, 100, 150, 250, 500}

	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case <-e.done:
			return
		case <-t.C:
			e.outputResolvedNames()
		default:
			element, ok := e.outputQueue.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue loop
			}

			output := element.(*requests.Output)
			if !e.filters.Output.Duplicate(output.Name) {
				e.Output <- output
			}
		}
	}
}

func (e *Enumeration) outputResolvedNames() {
	var failed []*requests.DNSRequest

	// Prepare discovered names for output processing
	for {
		element, ok := e.resolvedQueue.Next()
		if !ok {
			break
		}

		name := element.(*requests.DNSRequest)

		output := e.buildOutput(name)
		if output == nil {
			failed = append(failed, name)
			continue
		}

		e.outputQueue.Append(output)
	}

	// Put failed attempts back on the resolved names queue
	for _, f := range failed {
		e.resolvedQueue.Append(f)
	}
}

func (e *Enumeration) buildOutput(req *requests.DNSRequest) *requests.Output {
	output := &requests.Output{
		Name:   req.Name,
		Domain: req.Domain,
		Tag:    req.Tag,
		Source: req.Source,
	}

	for _, r := range req.Records {
		if t := uint16(r.Type); t != dns.TypeA && t != dns.TypeAAAA {
			continue
		}

		addrInfo := e.buildAddrInfo(strings.TrimSpace(r.Data))
		if addrInfo == nil {
			return nil
		}

		output.Addresses = append(output.Addresses, *addrInfo)
	}

	return output
}

func (e *Enumeration) buildAddrInfo(addr string) *requests.AddressInfo {
	ainfo := &requests.AddressInfo{Address: net.ParseIP(addr)}

	asn := e.ipSearch(addr)
	if asn == nil {
		return nil
	}

	var err error
	ainfo.CIDRStr = asn.Prefix
	_, ainfo.Netblock, err = net.ParseCIDR(asn.Prefix)
	if err != nil || !ainfo.Netblock.Contains(ainfo.Address) {
		return nil
	}

	ainfo.ASN = asn.ASN
	ainfo.Description = asn.Description

	return ainfo
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
