// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
)

const (
	networksdbBaseURL = "https://networksdb.io"
	networksdbAPIPATH = "/api/v1"
)

var (
	networksdbOrgLinkRE = regexp.MustCompile(`ISP\/Organisation:<\/b> <a class="link_sm" href="(.*)"`)
	networksdbASNRE     = regexp.MustCompile(`Assigned AS:</b>.*href="/autonomous-system/AS.*">AS(.*)<\/a>`)
	networksdbCIDRRE    = regexp.MustCompile(`CIDR:<\/b>(.*)<br>`)
	networksdbASNameRE  = regexp.MustCompile(`AS Name:<\/b>(.*)<br>`)
	networksdbCCRE      = regexp.MustCompile(`Location:<\/b>.*href="/country/(.*)">`)
)

// NetworksDB is the Service that handles access to the NetworksDB.io data source.
type NetworksDB struct {
	BaseService

	API        *config.APIKey
	SourceType string
	hasAPIKey  bool
}

// NewNetworksDB returns he object initialized, but not yet started.
func NewNetworksDB(sys System) *NetworksDB {
	n := &NetworksDB{
		SourceType: requests.API,
		hasAPIKey:  true,
	}

	n.BaseService = *NewBaseService(n, "NetworksDB", sys)
	return n
}

// Type implements the Service interface.
func (n *NetworksDB) Type() string {
	return n.SourceType
}

// OnStart implements the Service interface.
func (n *NetworksDB) OnStart() error {
	n.BaseService.OnStart()

	n.API = n.System().Config().GetAPIKey(n.String())
	if n.API == nil || n.API.Key == "" {
		n.System().Config().Log.Printf("%s: API key data was not provided", n.String())
		n.SourceType = requests.SCRAPE
		n.hasAPIKey = false
	}

	n.SetRateLimit(3 * time.Second)
	return nil
}

// OnASNRequest implements the Service interface.
func (n *NetworksDB) OnASNRequest(ctx context.Context, req *requests.ASNRequest) {
	if req.Address == "" && req.ASN == 0 {
		return
	}

	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	n.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, n.String())

	if n.hasAPIKey {
		if req.Address != "" {
			n.executeAPIASNAddrQuery(ctx, req.Address)
		} else {
			n.executeAPIASNQuery(ctx, req.ASN, "", nil)
		}
		return
	}

	if req.Address != "" {
		n.executeASNAddrQuery(ctx, req.Address)
	} else {
		n.executeASNQuery(ctx, req.ASN, "", stringset.New())
	}
}

func (n *NetworksDB) executeASNAddrQuery(ctx context.Context, addr string) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	u := n.getIPURL(addr)
	page, err := http.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return
	}

	matches := networksdbOrgLinkRE.FindStringSubmatch(page)
	if matches == nil || len(matches) < 2 {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to extract the organization info href", n.String(), u),
		)
		return
	}

	n.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, n.String())

	u = networksdbBaseURL + matches[1]
	page, err = http.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return
	}

	netblocks := stringset.New()
	for _, match := range networksdbCIDRRE.FindAllStringSubmatch(page, -1) {
		if len(match) >= 2 {
			netblocks.Insert(strings.TrimSpace(match[1]))
		}
	}

	matches = networksdbASNRE.FindStringSubmatch(page)
	if matches == nil || len(matches) < 2 {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: The regular expression failed to extract the ASN", n.String(), u),
		)
		return
	}

	asn, err := strconv.Atoi(strings.TrimSpace(matches[1]))
	if err != nil {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to extract a valid ASN", n.String(), u),
		)
		return
	}

	n.executeASNQuery(ctx, asn, addr, netblocks)
}

func (n *NetworksDB) getIPURL(addr string) string {
	return networksdbBaseURL + "/ip/" + addr
}

func (n *NetworksDB) executeASNQuery(ctx context.Context, asn int, addr string, netblocks stringset.Set) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	n.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, n.String())

	u := n.getASNURL(asn)
	page, err := http.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return
	}

	matches := networksdbASNameRE.FindStringSubmatch(page)
	if matches == nil || len(matches) < 2 {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: The regular expression failed to extract the AS name", n.String()),
		)
		return
	}
	name := strings.TrimSpace(matches[1])

	matches = networksdbCCRE.FindStringSubmatch(page)
	if matches == nil || len(matches) < 2 {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: The regular expression failed to extract the country code", n.String()),
		)
		return
	}
	cc := strings.TrimSpace(matches[1])

	for _, match := range networksdbCIDRRE.FindAllStringSubmatch(page, -1) {
		if len(match) >= 2 {
			netblocks.Insert(strings.TrimSpace(match[1]))
		}
	}

	var prefix string
	if addr != "" {
		ip := net.ParseIP(addr)

		for cidr := range netblocks {
			if _, ipnet, err := net.ParseCIDR(cidr); err == nil && ipnet.Contains(ip) {
				prefix = cidr
				break
			}
		}
	}
	if prefix == "" && len(netblocks) > 0 {
		prefix = netblocks.Slice()[0] // TODO order may matter here :shrug:
	}

	bus.Publish(requests.NewASNTopic, &requests.ASNRequest{
		Address:     addr,
		ASN:         asn,
		Prefix:      prefix,
		CC:          cc,
		Description: name + ", " + cc,
		Netblocks:   netblocks,
		Tag:         n.SourceType,
		Source:      n.String(),
	})
}

func (n *NetworksDB) getASNURL(asn int) string {
	return networksdbBaseURL + "/autonomous-system/AS" + strconv.Itoa(asn)
}

func (n *NetworksDB) executeAPIASNAddrQuery(ctx context.Context, addr string) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	_, id := n.apiIPQuery(ctx, addr)
	if id == "" {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to obtain IP address information", n.String(), addr),
		)
		return
	}

	n.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, n.String())

	asns := n.apiOrgInfoQuery(ctx, id)
	if len(asns) == 0 {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to obtain ASNs associated with the organization", n.String(), id),
		)
		return
	}

	var asn int
	cidrs := stringset.New()
	ip := net.ParseIP(addr)
loop:
	for _, a := range asns {
		n.CheckRateLimit()
		cidrs = n.apiNetblocksQuery(ctx, a)
		if len(cidrs) == 0 {
			bus.Publish(requests.LogTopic,
				fmt.Sprintf("%s: %d: Failed to obtain netblocks associated with the ASN", n.String(), a),
			)
		}

		for cidr := range cidrs {
			if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
				if ipnet.Contains(ip) {
					asn = a
					break loop
				}
			}
		}
	}

	if asn == 0 {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to obtain the ASN associated with the IP address", n.String(), addr),
		)
		return
	}
	n.executeAPIASNQuery(ctx, asn, addr, cidrs)
}

func (n *NetworksDB) executeAPIASNQuery(ctx context.Context, asn int, addr string, netblocks stringset.Set) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	if len(netblocks) == 0 {
		netblocks.Union(n.apiNetblocksQuery(ctx, asn))
		if len(netblocks) == 0 {
			bus.Publish(requests.LogTopic,
				fmt.Sprintf("%s: %d: Failed to obtain netblocks associated with the ASN", n.String(), asn),
			)
			return
		}
	}

	var prefix string
	if addr != "" {
		ip := net.ParseIP(addr)
		for cidr := range netblocks {
			if _, ipnet, err := net.ParseCIDR(cidr); err == nil && ipnet.Contains(ip) {
				prefix = cidr
				break
			}
		}
	}
	if prefix == "" {
		prefix = netblocks.Slice()[0]
	}

	n.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, n.String())

	req := n.apiASNInfoQuery(ctx, asn)
	if req == nil {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %d: Failed to obtain ASN information", n.String(), asn),
		)
		return
	}

	if addr != "" {
		req.Address = addr
	}
	req.Prefix = prefix
	req.Netblocks = netblocks
	bus.Publish(requests.NewASNTopic, req)
}

func (n *NetworksDB) apiIPQuery(ctx context.Context, addr string) (string, string) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return "", ""
	}

	n.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, n.String())

	u := n.getAPIIPURL()
	params := url.Values{"ip": {addr}}
	body := strings.NewReader(params.Encode())
	page, err := http.RequestWebPage(u, body, n.getHeaders(), "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return "", ""
	}

	var m struct {
		Error   string `json:"error"`
		Total   int    `json:"total"`
		Results []struct {
			Org struct {
				ID string `json:"id"`
			} `json:"organisation"`
			Network struct {
				CIDR string `json:"cidr"`
			} `json:"network"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return "", ""
	} else if m.Error != "" {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %s", n.String(), u, m.Error))
		return "", ""
	} else if m.Total == 0 || len(m.Results) == 0 {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: The request returned zero results", n.String(), u),
		)
		return "", ""
	}

	return m.Results[0].Network.CIDR, m.Results[0].Org.ID
}

func (n *NetworksDB) getAPIIPURL() string {
	return networksdbBaseURL + networksdbAPIPATH + "/ip/info"
}

func (n *NetworksDB) apiOrgInfoQuery(ctx context.Context, id string) []int {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return []int{}
	}

	n.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, n.String())

	u := n.getAPIOrgInfoURL()
	params := url.Values{"id": {id}}
	body := strings.NewReader(params.Encode())
	page, err := http.RequestWebPage(u, body, n.getHeaders(), "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return []int{}
	}

	var m struct {
		Error   string `json:"error"`
		Total   int    `json:"total"`
		Results []struct {
			ASNs []int `json:"asns"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return []int{}
	} else if m.Error != "" {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %s", n.String(), u, m.Error))
		return []int{}
	} else if m.Total == 0 || len(m.Results[0].ASNs) == 0 {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: The request returned zero results", n.String(), u),
		)
		return []int{}
	}

	return m.Results[0].ASNs
}

func (n *NetworksDB) getAPIOrgInfoURL() string {
	return networksdbBaseURL + networksdbAPIPATH + "/org/info"
}

func (n *NetworksDB) apiASNInfoQuery(ctx context.Context, asn int) *requests.ASNRequest {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return nil
	}

	n.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, n.String())

	u := n.getAPIASNInfoURL()
	params := url.Values{"asn": {strconv.Itoa(asn)}}
	body := strings.NewReader(params.Encode())
	page, err := http.RequestWebPage(u, body, n.getHeaders(), "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return nil
	}

	var m struct {
		Error   string `json:"error"`
		Total   int    `json:"total"`
		Results []struct {
			ASN         int    `json:"asn"`
			ASName      string `json:"as_name"`
			Description string `json:"description"`
			CountryCode string `json:"countrycode"`
			Country     string `json:"country"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return nil
	} else if m.Error != "" {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %s", n.String(), u, m.Error))
		return nil
	} else if m.Total == 0 || len(m.Results) == 0 {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: The request returned zero results", n.String(), u),
		)
		return nil
	}

	return &requests.ASNRequest{
		ASN:         m.Results[0].ASN,
		CC:          m.Results[0].CountryCode,
		Description: m.Results[0].Description + ", " + m.Results[0].CountryCode,
		Tag:         n.SourceType,
		Source:      n.String(),
	}
}

func (n *NetworksDB) getAPIASNInfoURL() string {
	return networksdbBaseURL + networksdbAPIPATH + "/as/info"
}

func (n *NetworksDB) apiNetblocksQuery(ctx context.Context, asn int) stringset.Set {
	netblocks := stringset.New()

	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return netblocks
	}

	n.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, n.String())

	u := n.getAPINetblocksURL()
	params := url.Values{"asn": {strconv.Itoa(asn)}}
	body := strings.NewReader(params.Encode())
	page, err := http.RequestWebPage(u, body, n.getHeaders(), "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return netblocks
	}

	var m struct {
		Error   string `json:"error"`
		Total   int    `json:"total"`
		Results []struct {
			CIDR string `json:"cidr"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return netblocks
	} else if m.Error != "" {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %s", n.String(), u, m.Error))
		return netblocks
	} else if m.Total == 0 || len(m.Results) == 0 {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: The request returned zero results", n.String(), u),
		)
		return netblocks
	}

	for _, block := range m.Results {
		netblocks.Insert(block.CIDR)
	}
	return netblocks
}

func (n *NetworksDB) getAPINetblocksURL() string {
	return networksdbBaseURL + networksdbAPIPATH + "/as/networks"
}

func (n *NetworksDB) getHeaders() map[string]string {
	if !n.hasAPIKey {
		return nil
	}

	return map[string]string{
		"X-Api-Key":    n.API.Key,
		"Content-Type": "application/x-www-form-urlencoded",
	}
}
