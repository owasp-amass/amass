// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/OWASP/Amass/v3/stringset"
)

// Umbrella is the Service that handles access to the Umbrella data source.
type Umbrella struct {
	BaseService

	API        *config.APIKey
	SourceType string
}

// NewUmbrella returns he object initialized, but not yet started.
func NewUmbrella(sys System) *Umbrella {
	u := &Umbrella{SourceType: requests.API}

	u.BaseService = *NewBaseService(u, "Umbrella", sys)
	return u
}

// Type implements the Service interface.
func (u *Umbrella) Type() string {
	return u.SourceType
}

// OnStart implements the Service interface.
func (u *Umbrella) OnStart() error {
	u.BaseService.OnStart()

	u.API = u.System().Config().GetAPIKey(u.String())
	if u.API == nil || u.API.Key == "" {
		u.System().Config().Log.Printf("%s: API key data was not provided", u.String())
	}

	u.SetRateLimit(500 * time.Millisecond)
	return nil
}

// OnDNSRequest implements the Service interface.
func (u *Umbrella) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if u.API == nil || u.API.Key == "" {
		return
	}

	if !cfg.IsDomainInScope(req.Domain) {
		return
	}

	u.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, u.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", u.String(), req.Domain))

	headers := u.restHeaders()
	url := u.restDNSURL(req.Domain)
	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
		return
	}
	// Extract the subdomain names from the REST API results
	var subs struct {
		Matches []struct {
			Name string `json:"name"`
		} `json:"matches"`
	}
	if err := json.Unmarshal([]byte(page), &subs); err != nil {
		return
	}

	for _, m := range subs.Matches {
		if d := cfg.WhichDomain(m.Name); d != "" {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   m.Name,
				Domain: d,
				Tag:    u.SourceType,
				Source: u.String(),
			})
		}
	}
}

// OnAddrRequest implements the Service interface.
func (u *Umbrella) OnAddrRequest(ctx context.Context, req *requests.AddrRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if u.API == nil || u.API.Key == "" {
		return
	}

	if req.Address == "" {
		return
	}

	u.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, u.String())

	headers := u.restHeaders()
	url := u.restAddrURL(req.Address)
	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
		return
	}
	// Extract the subdomain names from the REST API results
	var ip struct {
		Records []struct {
			Data string `json:"rr"`
		} `json:"records"`
	}
	if err := json.Unmarshal([]byte(page), &ip); err != nil {
		return
	}

	for _, record := range ip.Records {
		if name := resolvers.RemoveLastDot(record.Data); name != "" {
			if domain := cfg.WhichDomain(name); domain != "" {
				bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
					Name:   name,
					Domain: req.Domain,
					Tag:    u.SourceType,
					Source: u.String(),
				})
			}
		}
	}
}

// OnASNRequest implements the Service interface.
func (u *Umbrella) OnASNRequest(ctx context.Context, req *requests.ASNRequest) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	if u.API == nil || u.API.Key == "" {
		return
	}

	if req.Address == "" && req.ASN == 0 {
		return
	}

	u.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, u.String())

	if req.Address != "" {
		u.executeASNAddrQuery(ctx, req)
		return
	}

	u.executeASNQuery(ctx, req)
}

func (u *Umbrella) executeASNAddrQuery(ctx context.Context, req *requests.ASNRequest) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	headers := u.restHeaders()
	url := u.restAddrToASNURL(req.Address)
	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
		return
	}
	// Extract the AS information from the REST API results
	var as []struct {
		Date        string `json:"creation_date"`
		Registry    int    `json:"ir"`
		Description string `json:"description"`
		ASN         int    `json:"asn"`
		CIDR        string `json:"cidr"`
	}
	if err := json.Unmarshal([]byte(page), &as); err != nil || len(as) == 0 {
		return
	}

	created, err := time.Parse("2006-01-02", as[0].Date)
	if err != nil {
		return
	}

	var registry string
	switch as[0].Registry {
	case 1:
		registry = "AfriNIC"
	case 2:
		registry = "APNIC"
	case 3:
		registry = "ARIN"
	case 4:
		registry = "LACNIC"
	case 5:
		registry = "RIPE NCC"
	default:
		registry = "N/A"
	}

	req.ASN = as[0].ASN
	req.Prefix = as[0].CIDR
	req.Registry = registry
	req.AllocationDate = created
	req.Description = as[0].Description
	req.Tag = u.SourceType
	req.Source = u.String()
	if req.Netblocks == nil {
		req.Netblocks = stringset.New()
		req.Netblocks.Insert(strings.TrimSpace(req.Prefix))

		u.CheckRateLimit()
		bus.Publish(requests.SetActiveTopic, u.String())

		u.executeASNQuery(ctx, req)
	}
	bus.Publish(requests.NewASNTopic, req)
}

func (u *Umbrella) executeASNQuery(ctx context.Context, req *requests.ASNRequest) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	headers := u.restHeaders()
	url := u.restASNToCIDRsURL(req.ASN)
	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
		return
	}
	// Extract the netblock information from the REST API results
	var netblock []struct {
		CIDR string `json:"cidr"`
		Geo  struct {
			CountryName string `json:"country_name"`
			CountryCode string `json:"country_code"`
		} `json:"geo"`
	}
	if err := json.Unmarshal([]byte(page), &netblock); err != nil || len(netblock) == 0 {
		return
	}

	if req.Netblocks == nil {
		req.Netblocks = stringset.New()
	}

	for _, nb := range netblock {
		req.Netblocks.Insert(strings.TrimSpace(nb.CIDR))
		if nb.CIDR == req.Prefix {
			req.CC = nb.Geo.CountryCode
		}
	}
	// If no basic AS info exists, then obtain an IP and query
	if req.Prefix == "" {
		addr, _, err := net.ParseCIDR(netblock[0].CIDR)

		if err == nil {
			req.Address = addr.String()
			req.CC = netblock[0].Geo.CountryCode

			u.CheckRateLimit()
			bus.Publish(requests.SetActiveTopic, u.String())

			u.executeASNAddrQuery(ctx, req)
			return
		}
	}
	// Finish populating the AS info in the request
	for _, nb := range netblock {
		if nb.CIDR == req.Prefix {
			req.CC = nb.Geo.CountryCode
			break
		}
	}
}

// Umbrella provides much more than this, but we're only interested in these
// fields
type whoisRecord struct {
	NameServers         []string `json:"nameServers"`
	AdminContactEmail   string   `json:"administrativeContactEmail"`
	BillingContactEmail string   `json:"billingContactEmail"`
	RegistrantEmail     string   `json:"registrantEmail"`
	TechContactEmail    string   `json:"technicalContactEmail"`
	ZoneContactEmail    string   `json:"zoneContactEmail"`
}

// Umbrella provides the same response for email and ns reverse records. Makes
// the json parsing logic simple since we can use the same structs for both
type rWhoisDomain struct {
	Domain  string `json:"domain"`
	Current bool   `json:"current"`
}

type rWhoisResponse struct {
	TotalResults int            `json:"totalResults"`
	MoreData     bool           `json:"moreDataAvailable"`
	Limit        int            `json:"limit"`
	Domains      []rWhoisDomain `json:"domains"`
}

func (u *Umbrella) collateEmails(ctx context.Context, record *whoisRecord) []string {
	emails := stringset.New()

	if u.validateScope(ctx, record.AdminContactEmail) {
		emails.InsertMany(record.AdminContactEmail)
	}
	if u.validateScope(ctx, record.BillingContactEmail) {
		emails.InsertMany(record.BillingContactEmail)
	}
	if u.validateScope(ctx, record.RegistrantEmail) {
		emails.InsertMany(record.RegistrantEmail)
	}
	if u.validateScope(ctx, record.TechContactEmail) {
		emails.InsertMany(record.TechContactEmail)
	}
	if u.validateScope(ctx, record.ZoneContactEmail) {
		emails.InsertMany(record.ZoneContactEmail)
	}
	return emails.Slice()
}

func (u *Umbrella) queryWhois(ctx context.Context, domain string) *whoisRecord {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return nil
	}

	var whois whoisRecord
	headers := u.restHeaders()
	whoisURL := u.whoisRecordURL(domain)

	u.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, u.String())

	record, err := http.RequestWebPage(whoisURL, nil, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), whoisURL, err))
		return nil
	}

	err = json.Unmarshal([]byte(record), &whois)
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), whoisURL, err))
		return nil
	}
	return &whois
}

func (u *Umbrella) queryReverseWhois(ctx context.Context, apiURL string) []string {
	domains := stringset.New()
	headers := u.restHeaders()
	var whois map[string]rWhoisResponse

	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return domains.Slice()
	}

	// Umbrella provides data in 500 piece chunks
	for count, more := 0, true; more; count = count + 500 {
		u.CheckRateLimit()
		bus.Publish(requests.SetActiveTopic, u.String())

		fullAPIURL := fmt.Sprintf("%s&offset=%d", apiURL, count)
		record, err := http.RequestWebPage(fullAPIURL, nil, headers, "", "")
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), apiURL, err))
			return domains.Slice()
		}
		err = json.Unmarshal([]byte(record), &whois)

		more = false
		for _, result := range whois {
			if result.TotalResults > 0 {
				for _, domain := range result.Domains {
					if domain.Current {
						domains.Insert(domain.Domain)
					}
				}
			}
			if result.MoreData && more == false {
				more = true
			}
		}
	}
	return domains.Slice()
}

func (u *Umbrella) validateScope(ctx context.Context, input string) bool {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	if cfg == nil {
		return false
	}

	if input != "" && cfg.IsDomainInScope(input) {
		return true
	}
	return false
}

// OnWhoisRequest implements the Service interface.
func (u *Umbrella) OnWhoisRequest(ctx context.Context, req *requests.WhoisRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if u.API == nil || u.API.Key == "" {
		return
	}

	if !cfg.IsDomainInScope(req.Domain) {
		return
	}

	whoisRecord := u.queryWhois(ctx, req.Domain)
	if whoisRecord == nil {
		return
	}

	domains := stringset.New()
	emails := u.collateEmails(ctx, whoisRecord)
	if len(emails) > 0 {
		emailURL := u.reverseWhoisByEmailURL(emails...)
		for _, d := range u.queryReverseWhois(ctx, emailURL) {
			if !cfg.IsDomainInScope(d) {
				domains.Insert(d)
			}
		}
	}

	var nameservers []string
	for _, ns := range whoisRecord.NameServers {
		if u.validateScope(ctx, ns) {
			nameservers = append(nameservers, ns)
		}
	}
	if len(nameservers) > 0 {
		nsURL := u.reverseWhoisByNSURL(nameservers...)
		for _, d := range u.queryReverseWhois(ctx, nsURL) {
			if !cfg.IsDomainInScope(d) {
				domains.Insert(d)
			}
		}
	}

	if len(domains) > 0 {
		bus.Publish(requests.NewWhoisTopic, &requests.WhoisRequest{
			Domain:     req.Domain,
			NewDomains: domains.Slice(),
			Tag:        u.SourceType,
			Source:     u.String(),
		})
	}
}

func (u *Umbrella) restHeaders() map[string]string {
	headers := map[string]string{"Content-Type": "application/json"}

	if u.API != nil && u.API.Key != "" {
		headers["Authorization"] = "Bearer " + u.API.Key
	}
	return headers

}

func (u *Umbrella) whoisBaseURL() string {
	return `https://investigate.api.umbrella.com/whois/`
}

func (u *Umbrella) whoisRecordURL(domain string) string {
	return u.whoisBaseURL() + domain
}

func (u *Umbrella) reverseWhoisByNSURL(ns ...string) string {
	nameservers := strings.Join(ns, ",")

	return u.whoisBaseURL() + `nameservers?nameServerList=` + nameservers
}

func (u *Umbrella) reverseWhoisByEmailURL(emails ...string) string {
	emailQuery := strings.Join(emails, ",")

	return u.whoisBaseURL() + `emails?emailList=` + emailQuery
}

func (u *Umbrella) restDNSURL(domain string) string {
	return `https://investigate.api.umbrella.com/search/.*[.]` + domain + "?start=-30days&limit=1000"
}

func (u *Umbrella) restAddrURL(addr string) string {
	return "https://investigate.api.umbrella.com/pdns/ip/" + addr + "?recordType=A,AAAA"
}

func (u *Umbrella) restAddrToASNURL(addr string) string {
	return fmt.Sprintf("https://investigate.api.umbrella.com/bgp_routes/ip/%s/as_for_ip.json", addr)
}

func (u *Umbrella) restASNToCIDRsURL(asn int) string {
	return fmt.Sprintf("https://investigate.api.umbrella.com/bgp_routes/asn/%d/prefixes_for_asn.json", asn)
}
