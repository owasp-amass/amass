// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// AddressService is the Service that handles all newly discovered IP addresses
// within the architecture. This is achieved by receiving all the NEWADDR events.
type AddressService struct {
	core.BaseService

	filter *utils.StringFilter
}

// NewAddressService returns he object initialized, but not yet started.
func NewAddressService(config *core.Config, bus *core.EventBus) *AddressService {
	as := &AddressService{filter: utils.NewStringFilter()}

	as.BaseService = *core.NewBaseService(as, "Address Service", config, bus)
	return as
}

// OnStart implements the Service interface
func (as *AddressService) OnStart() error {
	as.BaseService.OnStart()

	as.Bus().Subscribe(core.NewAddrTopic, as.SendRequest)
	go as.processRequests()
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

func (as *AddressService) performRequest(req *core.Request) {
	if req == nil || req.Address == "" {
		return
	}
	as.SetActive()

	if as.filter.Duplicate(req.Address) {
		return
	}
	as.Bus().Publish(core.ActiveCertTopic, req)

	_, cidr, _, err := IPRequest(req.Address)
	if err != nil {
		as.Config().Log.Printf("%v", err)
		return
	}
	as.Bus().Publish(core.ReverseSweepTopic, req.Address, cidr)
}
