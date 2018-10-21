// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/OWASP/Amass/amass/core"
	evbus "github.com/asaskevich/EventBus"
	"github.com/miekg/dns"
)

// AlterationService is the AmassService that handles all DNS name permutation within
// the architecture. This is achieved by receiving all the RESOLVED events.
type AlterationService struct {
	core.BaseAmassService

	bus evbus.Bus
}

// NewAlterationService requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewAlterationService(config *core.AmassConfig, bus evbus.Bus) *AlterationService {
	as := &AlterationService{bus: bus}

	as.BaseAmassService = *core.NewBaseAmassService("Alteration Service", config, as)
	return as
}

// OnStart implements the AmassService interface
func (as *AlterationService) OnStart() error {
	as.BaseAmassService.OnStart()

	if as.Config().Alterations {
		as.bus.SubscribeAsync(core.RESOLVED, as.SendRequest, false)
		go as.processRequests()
	}
	return nil
}

// OnStop implements the AmassService interface
func (as *AlterationService) OnStop() error {
	as.BaseAmassService.OnStop()

	if as.Config().Alterations {
		as.bus.Unsubscribe(core.RESOLVED, as.SendRequest)
	}
	return nil
}

func (as *AlterationService) processRequests() {
	t := time.NewTicker(10 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			if req := as.NextRequest(); req != nil {
				as.executeAlterations(req)
			}
		case <-as.PauseChan():
			t.Stop()
		case <-as.ResumeChan():
			t = time.NewTicker(10 * time.Millisecond)
		case <-as.Quit():
			return
		}
	}
}

// executeAlterations runs all the DNS name alteration methods as goroutines.
func (as *AlterationService) executeAlterations(req *core.AmassRequest) {
	if !as.Config().IsDomainInScope(req.Name) || !as.correctRecordTypes(req) {
		return
	}
	as.flipNumbersInName(req)
	as.appendNumbers(req)
}

func (as *AlterationService) correctRecordTypes(req *core.AmassRequest) bool {
	var ok bool

	for _, r := range req.Records {
		t := uint16(r.Type)

		if t == dns.TypeTXT || t == dns.TypeA || t == dns.TypeAAAA || t == dns.TypeCNAME {
			ok = true
			break
		}
	}
	return ok
}

// flipNumbersInName flips numbers in a subdomain name.
func (as *AlterationService) flipNumbersInName(req *core.AmassRequest) {
	n := req.Name
	parts := strings.SplitN(n, ".", 2)
	// Find the first character that is a number
	first := strings.IndexFunc(parts[0], unicode.IsNumber)
	if first < 0 {
		return
	}
	// Flip the first number and attempt a second number
	for i := 0; i < 10; i++ {
		sf := n[:first] + strconv.Itoa(i) + n[first+1:]

		as.secondNumberFlip(sf, req.Domain, first+1)
	}
	// Take the first number out
	as.secondNumberFlip(n[:first]+n[first+1:], req.Domain, -1)
}

func (as *AlterationService) secondNumberFlip(name, domain string, minIndex int) {
	parts := strings.SplitN(name, ".", 2)

	as.SetActive()
	// Find the second character that is a number
	last := strings.LastIndexFunc(parts[0], unicode.IsNumber)
	if last < 0 || last < minIndex {
		as.sendAlteredName(name, domain)
		return
	}
	// Flip those numbers and send out the mutations
	for i := 0; i < 10; i++ {
		n := name[:last] + strconv.Itoa(i) + name[last+1:]

		as.sendAlteredName(n, domain)
	}
	// Take the second number out
	as.sendAlteredName(name[:last]+name[last+1:], domain)
}

// appendNumbers appends a number to a subdomain name.
func (as *AlterationService) appendNumbers(req *core.AmassRequest) {
	n := req.Name
	parts := strings.SplitN(n, ".", 2)

	as.SetActive()
	for i := 0; i < 10; i++ {
		// Send a LABEL-NUM altered name
		nhn := parts[0] + "-" + strconv.Itoa(i) + "." + parts[1]
		as.sendAlteredName(nhn, req.Domain)
		// Send a LABELNUM altered name
		nn := parts[0] + strconv.Itoa(i) + "." + parts[1]
		as.sendAlteredName(nn, req.Domain)
	}
}

// sendAlteredName checks that the provided name is valid and sends it along to the SubdomainService.
func (as *AlterationService) sendAlteredName(name, domain string) {
	re := as.Config().DomainRegex(domain)

	if re != nil && re.MatchString(name) {
		as.bus.Publish(core.NEWNAME, &core.AmassRequest{
			Name:   name,
			Domain: domain,
			Tag:    core.ALT,
			Source: "Alterations",
		})
	}
}
