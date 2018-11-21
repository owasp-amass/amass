// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// AddressService is the AmassService that handles all newly discovered IP addresses
// within the architecture. This is achieved by receiving all the NEWADDR events.
type AddressService struct {
	core.BaseAmassService

	Bus    evbus.Bus
	Config *core.AmassConfig
	filter *utils.StringFilter
}

// NewAddressService requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewAddressService(e *core.Enumeration, bus evbus.Bus, config *core.AmassConfig) *AddressService {
	as := &AddressService{
		Bus:    bus,
		Config: config,
		filter: utils.NewStringFilter(),
	}

	as.BaseAmassService = *core.NewBaseAmassService(e, "Address Service", as)
	return as
}

// OnStart implements the AmassService interface
func (as *AddressService) OnStart() error {
	as.BaseAmassService.OnStart()

	as.Bus.SubscribeAsync(core.NEWADDR, as.SendRequest, false)
	go as.processRequests()
	return nil
}

// OnStop implements the AmassService interface
func (as *AddressService) OnStop() error {
	as.BaseAmassService.OnStop()

	as.Bus.Unsubscribe(core.NEWADDR, as.SendRequest)
	return nil
}

func (as *AddressService) processRequests() {
	for {
		select {
		case <-as.PauseChan():
			<-as.ResumeChan()
		case <-as.Quit():
			return
		case req := <-as.RequestChan():
			go as.performRequest(req)
		}
	}
}

func (as *AddressService) performRequest(req *core.AmassRequest) {
	if req == nil || req.Address == "" || as.filter.Duplicate(req.Address) {
		return
	}

	as.SetActive()
	_, cidr, _, err := IPRequest(req.Address)
	if err != nil {
		as.Config.Log.Printf("%v", err)
		return
	}
	// Request the reverse DNS sweep for the addr
	as.Bus.Publish(core.DNSSWEEP, req.Address, cidr)
	if as.Config.Active {
		as.Bus.Publish(core.ACTIVECERT, req.Address)
	}
}
