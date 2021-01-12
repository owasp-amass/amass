// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	amassnet "github.com/OWASP/Amass/v3/net"
	amasshttp "github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/service"
	"github.com/caffix/stringset"
)

// IPToASN is the Service that handles access to the IPToASN data source.
type IPToASN struct {
	service.BaseService

	SourceType string
}

// NewIPToASN returns he object initialized, but not yet started.
func NewIPToASN(sys systems.System) *IPToASN {
	i := &IPToASN{SourceType: requests.API}

	i.BaseService = *service.NewBaseService(i, "IPToASN")
	return i
}

// Description implements the Service interface.
func (i *IPToASN) Description() string {
	return i.SourceType
}

// OnStart implements the Service interface.
func (i *IPToASN) OnStart() error {
	i.SetRateLimit(1)
	return nil
}

// OnRequest implements the Service interface.
func (i *IPToASN) OnRequest(ctx context.Context, args service.Args) {
	if req, ok := args.(*requests.ASNRequest); ok {
		i.asnRequest(ctx, req)
	}
}

func (i *IPToASN) asnRequest(ctx context.Context, req *requests.ASNRequest) {
	_, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return
	}

	if req.Address == "" {
		return
	}

	i.CheckRateLimit()
	r, err := i.getASInfo(req.Address)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: %v", i.String(), req.Address, err))
		return
	}

	r.Address = req.Address
	bus.Publish(requests.NewASNTopic, eventbus.PriorityHigh, r)
}

func (i *IPToASN) getASInfo(addr string) (*requests.ASNRequest, error) {
	u := i.getURL(addr)

	headers := map[string]string{"Accept": "application/json"}
	page, err := amasshttp.RequestWebPage(u, nil, headers, "", "")
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %v", i.String(), u, err)
	}

	// Extract the AS info from the results
	var m struct {
		ASN         int    `json:"as_number"`
		CountryCode string `json:"as_country_code"`
		First       string `json:"first_ip"`
		Last        string `json:"last_ip"`
		Description string `json:"as_description"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		return nil, fmt.Errorf("%s: %s: %v", i.String(), page, err)
	}

	netblock := amassnet.Range2CIDR(net.ParseIP(m.First), net.ParseIP(m.Last))
	if netblock == nil {
		return nil, fmt.Errorf("%s: Failed to obtain the AS netblock information", i.String())
	}

	return &requests.ASNRequest{
		ASN:         m.ASN,
		Prefix:      netblock.String(),
		CC:          m.CountryCode,
		Description: m.Description,
		Netblocks:   stringset.New(netblock.String()),
		Tag:         i.SourceType,
		Source:      i.String(),
	}, nil
}

func (i *IPToASN) getURL(addr string) string {
	format := "https://api.iptoasn.com/v1/as/ip/%s"

	return fmt.Sprintf(format, addr)
}
