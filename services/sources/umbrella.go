// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/stringset"
	"github.com/OWASP/Amass/utils"
)

// Umbrella is the Service that handles access to the Umbrella data source.
type Umbrella struct {
	services.BaseService

	API        *config.APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewUmbrella returns he object initialized, but not yet started.
func NewUmbrella(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *Umbrella {
	u := &Umbrella{
		SourceType: requests.API,
		RateLimit:  500 * time.Millisecond,
	}

	u.BaseService = *services.NewBaseService(u, "Umbrella", cfg, bus, pool)
	return u
}

// OnStart implements the Service interface
func (u *Umbrella) OnStart() error {
	u.BaseService.OnStart()

	u.API = u.Config().GetAPIKey(u.String())
	if u.API == nil || u.API.Key == "" {
		u.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: API key data was not provided", u.String()),
		)
	}

	go u.processRequests()
	return nil
}

func (u *Umbrella) processRequests() {
	last := time.Now()

	for {
		select {
		case <-u.Quit():
			return
		case req := <-u.DNSRequestChan():
			if u.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < u.RateLimit {
					time.Sleep(u.RateLimit)
				}
				last = time.Now()
				u.executeDNSQuery(req.Domain)
				last = time.Now()
			}
		case <-u.AddrRequestChan():
		case <-u.ASNRequestChan():
		case req := <-u.WhoisRequestChan():
			if u.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < u.RateLimit {
					time.Sleep(u.RateLimit)
				}
				last = time.Now()
				u.executeWhoisQuery(req.Domain)
				last = time.Now()
			}
		}
	}
}

func (u *Umbrella) executeDNSQuery(domain string) {
	re := u.Config().DomainRegex(domain)
	if re == nil || u.API == nil || u.API.Key == "" {
		return
	}

	u.SetActive()
	headers := u.restHeaders()
	url := u.patternSearchRestURL(domain)
	page, err := utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		u.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
		return
	}

	for _, name := range re.FindAllString(page, -1) {
		u.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    u.SourceType,
			Source: u.String(),
		})
	}

	url = u.occurrencesRestURL(domain)
	page, err = utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		u.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
		return
	}

	for _, d := range u.Config().Domains() {
		re := u.Config().DomainRegex(d)
		for _, sd := range re.FindAllString(page, -1) {
			u.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   cleanName(sd),
				Domain: d,
				Tag:    u.SourceType,
				Source: u.String(),
			})
		}
	}

	u.SetActive()
	url = u.relatedRestURL(domain)
	page, err = utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		u.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
		return
	}

	for _, d := range u.Config().Domains() {
		re := u.Config().DomainRegex(d)
		for _, sd := range re.FindAllString(page, -1) {
			u.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   cleanName(sd),
				Domain: d,
				Tag:    u.SourceType,
				Source: u.String(),
			})
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

func (u *Umbrella) collateEmails(record *whoisRecord) []string {
	emails := stringset.New()

	if u.validateScope(record.AdminContactEmail) {
		emails.InsertMany(record.AdminContactEmail)
	}
	if u.validateScope(record.BillingContactEmail) {
		emails.InsertMany(record.BillingContactEmail)
	}
	if u.validateScope(record.RegistrantEmail) {
		emails.InsertMany(record.RegistrantEmail)
	}
	if u.validateScope(record.TechContactEmail) {
		emails.InsertMany(record.TechContactEmail)
	}
	if u.validateScope(record.ZoneContactEmail) {
		emails.InsertMany(record.ZoneContactEmail)
	}
	return emails.ToSlice()
}

func (u *Umbrella) queryWhois(domain string) *whoisRecord {
	var whois whoisRecord
	headers := u.restHeaders()
	whoisURL := u.whoisRecordURL(domain)

	u.SetActive()
	record, err := utils.RequestWebPage(whoisURL, nil, headers, "", "")
	if err != nil {
		u.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), whoisURL, err))
		return nil
	}

	err = json.Unmarshal([]byte(record), &whois)
	if err != nil {
		u.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), whoisURL, err))
		return nil
	}

	u.SetActive()
	time.Sleep(u.RateLimit)
	return &whois
}

func (u *Umbrella) queryReverseWhois(apiURL string) []string {
	domains := stringset.New()
	headers := u.restHeaders()
	var whois map[string]rWhoisResponse

	// Umbrella provides data in 500 piece chunks
	for count, more := 0, true; more; count = count + 500 {
		u.SetActive()
		fullAPIURL := fmt.Sprintf("%s&offset=%d", apiURL, count)
		record, err := utils.RequestWebPage(fullAPIURL, nil, headers, "", "")
		if err != nil {
			u.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), apiURL, err))
			return domains.ToSlice()
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

		u.SetActive()
		time.Sleep(u.RateLimit)
	}
	return domains.ToSlice()
}

func (u *Umbrella) validateScope(input string) bool {
	if input != "" && u.Config().IsDomainInScope(input) {
		return true
	}
	return false
}

func (u *Umbrella) executeWhoisQuery(domain string) {
	if u.API == nil || u.API.Key == "" {
		return
	}

	whoisRecord := u.queryWhois(domain)
	if whoisRecord == nil {
		return
	}

	domains := stringset.New()
	emails := u.collateEmails(whoisRecord)
	if len(emails) > 0 {
		emailURL := u.reverseWhoisByEmailURL(emails...)
		for _, d := range u.queryReverseWhois(emailURL) {
			if !u.Config().IsDomainInScope(d) {
				domains.Insert(d)
			}
		}
	}

	var nameservers []string
	for _, ns := range whoisRecord.NameServers {
		if u.validateScope(ns) {
			nameservers = append(nameservers, ns)
		}
	}
	if len(nameservers) > 0 {
		nsURL := u.reverseWhoisByNSURL(nameservers...)
		for _, d := range u.queryReverseWhois(nsURL) {
			if !u.Config().IsDomainInScope(d) {
				domains.Insert(d)
			}
		}
	}

	if len(domains) > 0 {
		u.Bus().Publish(requests.NewWhoisTopic, &requests.WhoisRequest{
			Domain:     domain,
			NewDomains: domains.ToSlice(),
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

func (u *Umbrella) patternSearchRestURL(domain string) string {
	return `https://investigate.api.umbrella.com/search/.*[.]` + domain + "?start=-30days&limit=1000"
}

func (u *Umbrella) occurrencesRestURL(domain string) string {
	return "https://investigate.api.umbrella.com/recommendations/name/" + domain + ".json"
}

func (u *Umbrella) relatedRestURL(domain string) string {
	return "https://investigate.api.umbrella.com/links/name/" + domain + ".json"
}
