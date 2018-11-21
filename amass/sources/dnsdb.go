// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// DNSDB is the AmassService that handles access to the DNSDB data source.
type DNSDB struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	SourceType string
}

// NewDNSDB requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewDNSDB(e *core.Enumeration, bus evbus.Bus, config *core.AmassConfig) *DNSDB {
	d := &DNSDB{
		Bus:        bus,
		Config:     config,
		SourceType: core.SCRAPE,
	}

	d.BaseAmassService = *core.NewBaseAmassService(e, "DNSDB", d)
	return d
}

// OnStart implements the AmassService interface
func (d *DNSDB) OnStart() error {
	d.BaseAmassService.OnStart()

	go d.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (d *DNSDB) OnStop() error {
	d.BaseAmassService.OnStop()
	return nil
}

func (d *DNSDB) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range d.Config.Domains() {
		d.executeQuery(domain)
	}
}

func (d *DNSDB) executeQuery(domain string) {
	url := d.getURL(domain, domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		d.Config.Log.Printf("%s: %s: %v", d.String(), url, err)
		return
	}

	var names []string
	d.SetActive()
	re := d.Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(names, cleanName(sd)); len(u) > 0 {
			names = append(names, u...)
		}
	}

	t := time.NewTicker(time.Second)
	defer t.Stop()
loop:
	for _, rel := range d.getSubmatches(page) {
		d.SetActive()

		select {
		case <-d.Quit():
			break loop
		case <-t.C:
			another, err := utils.RequestWebPage(url+rel, nil, nil, "", "")
			if err != nil {
				d.Config.Log.Printf("%s: %s: %v", d.String(), url+rel, err)
				continue
			}

			for _, sd := range re.FindAllString(another, -1) {
				if u := utils.NewUniqueElements(names, cleanName(sd)); len(u) > 0 {
					names = append(names, u...)
				}
			}
		}
	}

	for _, n := range names {
		req := &core.AmassRequest{
			Name:   n,
			Domain: domain,
			Tag:    d.SourceType,
			Source: d.String(),
		}

		if d.Enum().DupDataSourceName(req) {
			continue
		}
		d.Bus.Publish(core.NEWNAME, req)
	}
}

func (d *DNSDB) getURL(domain, sub string) string {
	format := "http://www.dnsdb.org/%s/"
	url := fmt.Sprintf(format, domain)
	dparts := strings.Split(domain, ".")
	sparts := strings.Split(sub, ".")

	if len(dparts) == len(sparts) {
		return url
	}
	// Needs to be fixed
	delta := len(sparts) - len(dparts)
	for i := delta - 1; i >= 0; i-- {
		url += sparts[i]
		if i != 0 {
			url += "/"
		}
	}
	return url
}

func (d *DNSDB) getSubmatches(content string) []string {
	var results []string

	re := regexp.MustCompile("<br/><a href=\"([a-z0-9])\">[a-z0-9]</a>")
	for _, subs := range re.FindAllStringSubmatch(content, -1) {
		results = append(results, strings.TrimSpace(subs[1]))
	}
	return results
}
