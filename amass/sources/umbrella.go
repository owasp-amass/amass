// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
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
		RateLimit:  time.Second,
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
	go u.startRootDomains()
	return nil
}

func (u *Umbrella) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range u.Config().Domains() {
		u.executeQuery(domain)
		// Honor the rate limit
		time.Sleep(u.RateLimit)
	}
}

func (u *Umbrella) executeQuery(domain string) {
	if u.API == nil || u.API.Key == "" {
		return
	}

	headers := map[string]string{
		"Authorization": "Bearer " + u.API.Key,
		"Content-Type":  "application/json",
	}
	url := u.patternSearchRestURL(domain)
	page, err := utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		u.Config().Log.Printf("%s: %s: %v", u.String(), url, err)
		return
	}

	re := u.Config().DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		u.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   cleanName(sd),
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

	u.SetActive()
	for _, d := range u.Config().Domains() {
		re := u.Config().DomainRegex(d)
		for _, sd := range re.FindAllString(page, -1) {
			u.Bus().Publish(core.NewNameTopic, &core.Request{
				Name:   cleanName(sd),
				Domain: d,
				Tag:    u.SourceType,
				Source: u.String(),
			})
		}
	}

	url = u.relatedRestURL(domain)
	page, err = utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		u.Config().Log.Printf("%s: %s: %v", u.String(), url, err)
		return
	}

	u.SetActive()
	for _, d := range u.Config().Domains() {
		re := u.Config().DomainRegex(d)
		for _, sd := range re.FindAllString(page, -1) {
			u.Bus().Publish(core.NewNameTopic, &core.Request{
				Name:   cleanName(sd),
				Domain: d,
				Tag:    u.SourceType,
				Source: u.String(),
			})
		}
	}
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
