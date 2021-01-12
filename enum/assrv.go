// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/OWASP/Amass/v3/graph"
	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/service"
)

// ASService is the Service that handles all AS information collection for the architecture.
type ASService struct {
	service.BaseService
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

	as.BaseService = *service.NewBaseService(as, "AS Service")
	return as
}

// OnRequest implements the Service interface.
func (as *ASService) OnRequest(ctx context.Context, args service.Args) {
	if req, ok := args.(*requests.AddrRequest); ok {
		as.addrRequest(ctx, req)
	}
}

// InputAddress uses the provided AddrRequest argument to generate service requests.
func (as *ASService) InputAddress(req *requests.AddrRequest) {
	as.Request(context.TODO(), req)
}

func (as *ASService) addrRequest(ctx context.Context, req *requests.AddrRequest) {
	if r := as.sys.Cache().AddrSearch(req.Address); r != nil {
		as.Graph.InsertInfrastructure(r.ASN, r.Description, r.Address, r.Prefix, r.Source, r.Tag, as.uuid)
		return
	}

	for _, src := range as.sys.DataSources() {
		src.Request(ctx, &requests.ASNRequest{Address: req.Address})
	}

	for i := 0; i < 10; i++ {
		if as.sys.Cache().AddrSearch(req.Address) != nil {
			break
		}
		time.Sleep(time.Second)
	}

	if r := as.sys.Cache().AddrSearch(req.Address); r != nil && as.Graph != nil && as.uuid != "" {
		as.Graph.InsertInfrastructure(r.ASN, r.Description, r.Address, r.Prefix, r.Source, r.Tag, as.uuid)
	} else {
		as.Graph.InsertInfrastructure(0, "Unknown",
			req.Address, fakePrefix(req.Address), "RIR", requests.RIR, as.uuid)
	}

	as.Graph.HealAddressNodes(as.sys.Cache(), as.uuid)
}

func fakePrefix(addr string) string {
	bits := 24
	total := 32
	ip := net.ParseIP(addr)

	if amassnet.IsIPv6(ip) {
		bits = 48
		total = 128
	}

	mask := net.CIDRMask(bits, total)
	return fmt.Sprintf("%s/%d", ip.Mask(mask).String(), bits)
}
