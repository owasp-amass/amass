// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bufio"
	"encoding/json"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// Robtex is the AmassService that handles access to the Robtex data source.
type Robtex struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	SourceType string
}

type robtexJSON struct {
	Name string `json:"rrname"`
	Data string `json:"rrdata"`
	Type string `json:"rrtype"`
}

// NewRobtex requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewRobtex(bus evbus.Bus, config *core.AmassConfig) *Robtex {
	r := &Robtex{
		Bus:        bus,
		Config:     config,
		SourceType: core.API,
	}

	r.BaseAmassService = *core.NewBaseAmassService("Robtex", r)
	return r
}

// OnStart implements the AmassService interface
func (r *Robtex) OnStart() error {
	r.BaseAmassService.OnStart()

	go r.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (r *Robtex) OnStop() error {
	r.BaseAmassService.OnStop()
	return nil
}

func (r *Robtex) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range r.Config.Domains() {
		r.executeQuery(domain)
	}
}

func (r *Robtex) executeQuery(domain string) {
	var ips []string

	url := "https://freeapi.robtex.com/pdns/forward/" + domain
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		r.Config.Log.Printf("%s: %s: %v", r.String(), url, err)
		return
	}

	for _, line := range r.parseJSON(page) {
		if line.Type == "A" {
			ips = utils.UniqueAppend(ips, line.Data)
			// Inform the Address Service of this finding
			r.Bus.Publish(core.NEWADDR, &core.AmassRequest{
				Domain:  domain,
				Address: line.Data,
				Tag:     r.SourceType,
				Source:  r.String(),
			})
		}
	}

	var list string
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
loop:
	for _, ip := range ips {
		r.SetActive()

		select {
		case <-r.Quit():
			break loop
		case <-t.C:
			url = "https://freeapi.robtex.com/pdns/reverse/" + ip
			pdns, err := utils.RequestWebPage(url, nil, nil, "", "")
			if err != nil {
				r.Config.Log.Printf("%s: %s: %v", r.String(), url, err)
				continue
			}

			for _, line := range r.parseJSON(pdns) {
				list += line.Name + " "
			}
		}
	}

	r.SetActive()
	re := r.Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(list, -1) {
		n := cleanName(sd)

		if core.DataSourceNameFilter.Duplicate(n) {
			continue
		}

		r.Bus.Publish(core.NEWNAME, &core.AmassRequest{
			Name:   n,
			Domain: domain,
			Tag:    r.SourceType,
			Source: r.String(),
		})
	}
}

func (r *Robtex) parseJSON(page string) []robtexJSON {
	var lines []robtexJSON

	scanner := bufio.NewScanner(strings.NewReader(page))
	for scanner.Scan() {
		// Get the next line of JSON
		line := scanner.Text()
		if line == "" {
			continue
		}

		var j robtexJSON
		err := json.Unmarshal([]byte(line), &j)
		if err != nil {
			continue
		}
		lines = append(lines, j)
	}
	return lines
}
