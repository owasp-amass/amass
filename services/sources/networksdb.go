// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/net/http"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/stringset"
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
	services.BaseService

	API        *config.APIKey
	SourceType string
	RateLimit  time.Duration

	hasAPIKey bool
}

// NewNetworksDB returns he object initialized, but not yet started.
func NewNetworksDB(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *NetworksDB {
	n := &NetworksDB{
		SourceType: requests.API,
		RateLimit:  time.Second,
		hasAPIKey:  true,
	}

	n.BaseService = *services.NewBaseService(n, "NetworksDB", cfg, bus, pool)
	return n
}

// OnStart implements the Service interface
func (n *NetworksDB) OnStart() error {
	n.BaseService.OnStart()

	n.API = n.Config().GetAPIKey(n.String())
	if n.API == nil || n.API.Key == "" {
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: API key data was not provided", n.String()))
		n.SourceType = requests.SCRAPE
		n.hasAPIKey = false
	}

	n.Bus().Subscribe(requests.IPToASNTopic, n.SendASNRequest)
	go n.processRequests()
	return nil
}

func (n *NetworksDB) processRequests() {
	last := time.Now().Truncate(10 * time.Minute)
loop:
	for {
		select {
		case <-n.Quit():
			return
		case <-n.DNSRequestChan():
		case <-n.AddrRequestChan():
		case req := <-n.ASNRequestChan():
			if req.Address == "" && req.ASN == 0 {
				continue loop
			}
			if time.Now().Sub(last) < n.RateLimit {
				time.Sleep(n.RateLimit)
			}
			last = time.Now()
			if n.hasAPIKey {
				if req.Address != "" {
					n.executeAPIASNAddrQuery(req.Address)
				} else {
					n.executeAPIASNQuery(req.ASN, "", nil)
				}
			} else {
				if req.Address != "" {
					n.executeASNAddrQuery(req.Address)
				} else {
					n.executeASNQuery(req.ASN, "", stringset.New())
				}
			}
			last = time.Now()
		case <-n.WhoisRequestChan():
		}
	}
}

func (n *NetworksDB) executeASNAddrQuery(addr string) {
	n.SetActive()
	u := n.getIPURL(addr)
	page, err := http.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return
	}

	matches := networksdbOrgLinkRE.FindStringSubmatch(page)
	if matches == nil || len(matches) < 2 {
		n.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to extract the organization info href", n.String(), u),
		)
		return
	}

	n.SetActive()
	time.Sleep(n.RateLimit)
	u = networksdbBaseURL + matches[1]
	page, err = http.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
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
		n.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: The regular expression failed to extract the ASN", n.String(), u),
		)
		return
	}

	asn, err := strconv.Atoi(strings.TrimSpace(matches[1]))
	if err != nil {
		n.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to extract a valid ASN", n.String(), u),
		)
		return
	}

	n.SetActive()
	time.Sleep(n.RateLimit)
	n.executeASNQuery(asn, addr, netblocks)
}

func (n *NetworksDB) getIPURL(addr string) string {
	return networksdbBaseURL + "/ip/" + addr
}

func (n *NetworksDB) executeASNQuery(asn int, addr string, netblocks stringset.Set) {
	n.SetActive()
	u := n.getASNURL(asn)
	page, err := http.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return
	}

	matches := networksdbASNameRE.FindStringSubmatch(page)
	if matches == nil || len(matches) < 2 {
		n.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: The regular expression failed to extract the AS name", n.String()),
		)
		return
	}
	name := strings.TrimSpace(matches[1])

	matches = networksdbCCRE.FindStringSubmatch(page)
	if matches == nil || len(matches) < 2 {
		n.Bus().Publish(requests.LogTopic,
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

	n.Bus().Publish(requests.NewASNTopic, &requests.ASNRequest{
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

func (n *NetworksDB) executeAPIASNAddrQuery(addr string) {
	_, id := n.apiIPQuery(addr)
	if id == "" {
		n.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to obtain IP address information", n.String(), addr),
		)
		return
	}

	time.Sleep(n.RateLimit)
	asns := n.apiOrgInfoQuery(id)
	if len(asns) == 0 {
		n.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to obtain ASNs associated with the organization", n.String(), id),
		)
		return
	}

	var asn int
	cidrs := stringset.New()
	ip := net.ParseIP(addr)
loop:
	for _, a := range asns {
		time.Sleep(n.RateLimit)
		cidrs = n.apiNetblocksQuery(a)
		if len(cidrs) == 0 {
			n.Bus().Publish(requests.LogTopic,
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
		n.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to obtain the ASN associated with the IP address", n.String(), addr),
		)
		return
	}
	n.executeAPIASNQuery(asn, addr, cidrs)
}

func (n *NetworksDB) executeAPIASNQuery(asn int, addr string, netblocks stringset.Set) {
	if len(netblocks) == 0 {
		netblocks.Union(n.apiNetblocksQuery(asn))
		if len(netblocks) == 0 {
			n.Bus().Publish(requests.LogTopic,
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

	time.Sleep(n.RateLimit)
	req := n.apiASNInfoQuery(asn)
	if req == nil {
		n.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %d: Failed to obtain ASN information", n.String(), asn),
		)
		return
	}

	if addr != "" {
		req.Address = addr
	}
	req.Prefix = prefix
	req.Netblocks = netblocks
	n.Bus().Publish(requests.NewASNTopic, req)
}

func (n *NetworksDB) apiIPQuery(addr string) (string, string) {
	n.SetActive()
	u := n.getAPIIPURL()
	params := url.Values{"ip": {addr}}
	body := strings.NewReader(params.Encode())
	page, err := http.RequestWebPage(u, body, n.getHeaders(), "", "")
	if err != nil {
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
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
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return "", ""
	} else if m.Error != "" {
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %s", n.String(), u, m.Error))
		return "", ""
	} else if m.Total == 0 || len(m.Results) == 0 {
		n.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: The request returned zero results", n.String(), u),
		)
		return "", ""
	}

	return m.Results[0].Network.CIDR, m.Results[0].Org.ID
}

func (n *NetworksDB) getAPIIPURL() string {
	return networksdbBaseURL + networksdbAPIPATH + "/ip/info"
}

func (n *NetworksDB) apiOrgInfoQuery(id string) []int {
	n.SetActive()
	u := n.getAPIOrgInfoURL()
	params := url.Values{"id": {id}}
	body := strings.NewReader(params.Encode())
	page, err := http.RequestWebPage(u, body, n.getHeaders(), "", "")
	if err != nil {
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
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
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return []int{}
	} else if m.Error != "" {
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %s", n.String(), u, m.Error))
		return []int{}
	} else if m.Total == 0 || len(m.Results[0].ASNs) == 0 {
		n.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: The request returned zero results", n.String(), u),
		)
		return []int{}
	}

	return m.Results[0].ASNs
}

func (n *NetworksDB) getAPIOrgInfoURL() string {
	return networksdbBaseURL + networksdbAPIPATH + "/org/info"
}

func (n *NetworksDB) apiASNInfoQuery(asn int) *requests.ASNRequest {
	n.SetActive()
	u := n.getAPIASNInfoURL()
	params := url.Values{"asn": {strconv.Itoa(asn)}}
	body := strings.NewReader(params.Encode())
	page, err := http.RequestWebPage(u, body, n.getHeaders(), "", "")
	if err != nil {
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
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
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return nil
	} else if m.Error != "" {
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %s", n.String(), u, m.Error))
		return nil
	} else if m.Total == 0 || len(m.Results) == 0 {
		n.Bus().Publish(requests.LogTopic,
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

func (n *NetworksDB) apiNetblocksQuery(asn int) stringset.Set {
	netblocks := stringset.New()

	n.SetActive()
	u := n.getAPINetblocksURL()
	params := url.Values{"asn": {strconv.Itoa(asn)}}
	body := strings.NewReader(params.Encode())
	page, err := http.RequestWebPage(u, body, n.getHeaders(), "", "")
	if err != nil {
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
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
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), u, err))
		return netblocks
	} else if m.Error != "" {
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %s", n.String(), u, m.Error))
		return netblocks
	} else if m.Total == 0 || len(m.Results) == 0 {
		n.Bus().Publish(requests.LogTopic,
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
