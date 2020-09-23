// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"time"

	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
)

// ASService is the Service that handles all AS information collection for the architecture.
type ASService struct {
	requests.BaseService
	Graph      *graph.Graph
	SourceType string
	sys        systems.System
	uuid       string
}

// NewASService returns he object initialized, but not yet started.
func NewASService(sys systems.System, graph *graph.Graph, uuid string) *ASService {
	as := &ASService{
		Graph:      graph,
		SourceType: requests.RIR,
		sys:        sys,
		uuid:       uuid,
	}

	as.BaseService = *requests.NewBaseService(as, "AS Service")
	return as
}

// Type implements the Service interface.
func (as *ASService) Type() string {
	return as.SourceType
}

// OnAddrRequest implements the Service interface.
func (as *ASService) OnAddrRequest(ctx context.Context, req *requests.AddrRequest) {
	if r := as.sys.Cache().AddrSearch(req.Address); r != nil {
		as.Graph.InsertInfrastructure(r.ASN, r.Description, r.Address, r.Prefix, r.Source, r.Tag, as.uuid)
		return
	}

	for _, src := range as.sys.DataSources() {
		src.ASNRequest(ctx, &requests.ASNRequest{Address: req.Address})
	}

	for i := 0; i < 30; i++ {
		if as.sys.Cache().AddrSearch(req.Address) != nil {
			break
		}
		time.Sleep(time.Second)
	}

	if r := as.sys.Cache().AddrSearch(req.Address); r != nil && as.Graph != nil && as.uuid != "" {
		go as.Graph.InsertInfrastructure(r.ASN, r.Description, r.Address, r.Prefix, r.Source, r.Tag, as.uuid)
	}
}

// InputAddress uses the AddrRequest argument to lookup infrastructure information.
func (as *ASService) InputAddress(req *requests.AddrRequest) {
	as.AddrRequest(context.TODO(), req)
}
