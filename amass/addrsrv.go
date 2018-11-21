// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// AddressService is the AmassService that handles all newly discovered IP addresses
// within the architecture. This is achieved by receiving all the NEWADDR events.
type AddressService struct {
	core.BaseAmassService

	filter *utils.StringFilter
}

// NewAddressService returns he object initialized, but not yet started.
func NewAddressService(e *core.Enumeration) *AddressService {
	as := &AddressService{filter: utils.NewStringFilter()}

	as.BaseAmassService = *core.NewBaseAmassService(e, "Address Service", as)
	return as
}

// OnStart implements the AmassService interface
func (as *AddressService) OnStart() error {
	as.BaseAmassService.OnStart()

	as.Enum().Bus.SubscribeAsync(core.NEWADDR, as.SendRequest, false)
	go as.processRequests()
	return nil
}

// OnStop implements the AmassService interface
func (as *AddressService) OnStop() error {
	as.BaseAmassService.OnStop()

	as.Enum().Bus.Unsubscribe(core.NEWADDR, as.SendRequest)
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
		as.Enum().Log.Printf("%v", err)
		return
	}
	// Request the reverse DNS sweep for the addr
	as.Enum().Bus.Publish(core.DNSSWEEP, req.Address, cidr)
	if as.Enum().Config.Active {
		as.Enum().Bus.Publish(core.ACTIVECERT, req.Address)
	}
}
