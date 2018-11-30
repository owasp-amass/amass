// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"github.com/OWASP/Amass/amass/utils"
)

// AddressService is the Service that handles all newly discovered IP addresses
// within the architecture. This is achieved by receiving all the NEWADDR events.
type AddressService struct {
	BaseService

	filter *utils.StringFilter
}

// NewAddressService returns he object initialized, but not yet started.
func NewAddressService(e *Enumeration) *AddressService {
	as := &AddressService{filter: utils.NewStringFilter()}

	as.BaseService = *NewBaseService(e, "Address Service", as)
	return as
}

// OnStart implements the Service interface
func (as *AddressService) OnStart() error {
	as.BaseService.OnStart()

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

func (as *AddressService) performRequest(req *Request) {
	as.SetActive()

	if as.filter.Duplicate(req.Address) {
		return
	}
	as.Enum().ReverseDNSSweepEvent(req)
	as.Enum().ActiveCertEvent(req)
}
