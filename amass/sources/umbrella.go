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

	go u.processRequests()
	return nil
}

func (u *Umbrella) processRequests() {
	last := time.Now()

	for {
		select {
		case <-u.Quit():
			return
		case req := <-u.RequestChan():
			if u.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < u.RateLimit {
					time.Sleep(u.RateLimit)
				}
				last = time.Now()
				u.executeQuery(req.Domain)
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

	headers := map[string]string{
		"Authorization": "Bearer " + u.API.Key,
		"Content-Type":  "application/json",
	}
	u.SetActive()
	url := u.patternSearchRestURL(domain)
	page, err := utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		u.Config().Log.Printf("%s: %s: %v", u.String(), url, err)
		return
	}

	for _, name := range re.FindAllString(page, -1) {
		u.Bus().Publish(core.NewNameTopic, &core.Request{
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
			u.Bus().Publish(core.NewNameTopic, &core.Request{
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
