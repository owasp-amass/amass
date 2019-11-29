// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/OWASP/Amass/v3/eventbus"
	amassnet "github.com/OWASP/Amass/v3/net"
	amasshttp "github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
)

// IPToASN is the Service that handles access to the IPToASN data source.
type IPToASN struct {
	BaseService

	SourceType string
}

// NewIPToASN returns he object initialized, but not yet started.
func NewIPToASN(sys System) *IPToASN {
	i := &IPToASN{SourceType: requests.API}

	i.BaseService = *NewBaseService(i, "IPToASN", sys)
	return i
}

// Type implements the Service interface.
func (i *IPToASN) Type() string {
	return i.SourceType
}

// OnStart implements the Service interface.
func (i *IPToASN) OnStart() error {
	i.BaseService.OnStart()

	i.SetRateLimit(2 * time.Second)
	return nil
}

// OnASNRequest implements the Service interface.
func (i *IPToASN) OnASNRequest(ctx context.Context, req *requests.ASNRequest) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	if req.Address == "" {
		return
	}

	i.CheckRateLimit()
	//bus.Publish(requests.SetActiveTopic, i.String())

	r, err := i.getASInfo(req.Address)
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", i.String(), req.Address, err))
		return
	}

	r.Address = req.Address
	bus.Publish(requests.NewASNTopic, r)
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
