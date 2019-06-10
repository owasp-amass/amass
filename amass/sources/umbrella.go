// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// Umbrella is the Service that handles access to the Umbrella data source.
type Umbrella struct {
	core.BaseService

	API        *core.APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewUmbrella returns he object initialized, but not yet started.
func NewUmbrella(config *core.Config, bus *core.EventBus) *Umbrella {
	u := &Umbrella{
		SourceType: core.API,
		RateLimit:  500 * time.Millisecond,
	}

	u.BaseService = *core.NewBaseService(u, "Umbrella", config, bus)
	return u
}

// OnStart implements the Service interface
func (u *Umbrella) OnStart() error {
	u.BaseService.OnStart()

	u.API = u.Config().GetAPIKey(u.String())
	if u.API == nil || u.API.Key == "" {
		u.Config().Log.Printf("%s: API key data was not provided", u.String())
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
				u.executeQuery(req.Domain)
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

func (u *Umbrella) executeQuery(domain string) {
	re := u.Config().DomainRegex(domain)
	if re == nil || u.API == nil || u.API.Key == "" {
		return
	}

	headers := u.restHeaders()

	u.SetActive()
	url := u.patternSearchRestURL(domain)
	page, err := utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		u.Config().Log.Printf("%s: %s: %v", u.String(), url, err)
		return
	}

	for _, name := range re.FindAllString(page, -1) {
		u.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    u.SourceType,
			Source: u.String(),
		})
	}

	url = u.occurrencesRestURL(domain)
	page, err = utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		u.Config().Log.Printf("%s: %s: %v", u.String(), url, err)
		return
	}

	for _, d := range u.Config().Domains() {
		re := u.Config().DomainRegex(d)
		for _, sd := range re.FindAllString(page, -1) {
			u.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
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
		u.Config().Log.Printf("%s: %s: %v", u.String(), url, err)
		return
	}

	for _, d := range u.Config().Domains() {
		re := u.Config().DomainRegex(d)
		for _, sd := range re.FindAllString(page, -1) {
			u.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
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
	var emails []string

	if record.AdminContactEmail != "" {
		emails = utils.UniqueAppend(emails, record.AdminContactEmail)
	}
	if record.BillingContactEmail != "" {
		emails = utils.UniqueAppend(emails, record.BillingContactEmail)
	}
	if record.RegistrantEmail != "" {
		emails = utils.UniqueAppend(emails, record.RegistrantEmail)
	}
	if record.TechContactEmail != "" {
		emails = utils.UniqueAppend(emails, record.TechContactEmail)
	}
	if record.ZoneContactEmail != "" {
		emails = utils.UniqueAppend(emails, record.ZoneContactEmail)
	}

	return emails
}

func (u *Umbrella) queryWhois(domain string) *whoisRecord {
	var whois whoisRecord

	headers := u.restHeaders()

	whoisUrl := u.whoisRecordURL(domain)
	u.SetActive()
	record, err := utils.RequestWebPage(whoisUrl, nil, headers, "", "")
	if err != nil {
		u.Config().Log.Printf("%s: %s: %v", u.String(), whoisUrl, err)
		return nil
	}

	err = json.Unmarshal([]byte(record), &whois)
	if err != nil {
		u.Config().Log.Printf("%s: %s: %v", u.String(), whoisUrl, err)
		return nil
	}

	u.SetActive()
	time.Sleep(u.RateLimit)
	return &whois
}

func (u *Umbrella) queryReverseWhois(input []string, apiUrl string) []string {
	var domains []string

	if len(input) == 0 {
		return domains
	}

	headers := u.restHeaders()

	var whois map[string]rWhoisResponse

	// Umbrella provides data in 500 piece chunks
	for count, more := 0, true; more; count = count + 500 {
		u.SetActive()
		fullApiUrl := fmt.Sprintf("%s&offset=%d", apiUrl, count)
		record, err := utils.RequestWebPage(fullApiUrl, nil, headers, "", "")
		if err != nil {
			u.Config().Log.Printf("%s: %s: %v", u.String(), apiUrl, err)
			return domains
		}
		err = json.Unmarshal([]byte(record), &whois)

		more = false
		for _, result := range whois {
			if result.TotalResults > 0 {
				for _, domain := range result.Domains {
					if domain.Current {
						domains = utils.UniqueAppend(domains, domain.Domain)
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

	return domains
}

func (u *Umbrella) executeWhoisQuery(domain string) {
	var domains []string

	whoisRecord := u.queryWhois(domain)
	if whoisRecord == nil {
		return
	}

	emails := u.collateEmails(whoisRecord)
	emailUrl := u.reverseWhoisByEmailURL(emails...)
	domains = utils.UniqueAppend(domains, u.queryReverseWhois(emails, emailUrl)...)

	nsUrl := u.reverseWhoisByNSURL(whoisRecord.NameServers...)
	domains = utils.UniqueAppend(domains, u.queryReverseWhois(whoisRecord.NameServers, nsUrl)...)

	if len(domains) > 0 {
		u.Bus().Publish(core.NewWhoisTopic, &core.WhoisRequest{
			Domain:     domain,
			NewDomains: domains,
			Tag:        u.SourceType,
			Source:     u.String(),
		})
	}
}

func (u *Umbrella) restHeaders() map[string]string {
	headers := map[string]string{
		"Content-Type": "application/json",
	}
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
