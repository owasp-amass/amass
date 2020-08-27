// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"time"

	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/requests"
)

// ASService is the Service that handles all AS information collection for the architecture.
type ASService struct {
	requests.BaseService
	Cache      *net.ASNCache
	Graph      *graph.Graph
	SourceType string
	srcs       []requests.Service
	uuid       string
}

// NewASService returns he object initialized, but not yet started.
func NewASService(srcs []requests.Service, graph *graph.Graph, uuid string) *ASService {
	as := &ASService{
		Cache:      net.NewASNCache(),
		Graph:      graph,
		SourceType: requests.RIR,
		srcs:       srcs,
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
	if r := as.Cache.AddrSearch(req.Address); r != nil {
		go as.Graph.InsertInfrastructure(r.ASN, r.Description, r.Address, r.Prefix, r.Source, r.Tag, as.uuid)
		return
	}

	for _, src := range as.srcs {
		src.ASNRequest(ctx, &requests.ASNRequest{Address: req.Address})
	}

	for as.Cache.AddrSearch(req.Address) == nil {
		time.Sleep(time.Second)
	}

	if r := as.Cache.AddrSearch(req.Address); r != nil && as.Graph != nil && as.uuid != "" {
		go as.Graph.InsertInfrastructure(r.ASN, r.Description, r.Address, r.Prefix, r.Source, r.Tag, as.uuid)
	}
}
