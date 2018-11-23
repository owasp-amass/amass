// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"github.com/OWASP/Amass/amass/utils"
)

// OpenUKArchive is the AmassService that handles access to the OpenUKArchive data source.
type OpenUKArchive struct {
	BaseAmassService

	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewOpenUKArchive returns he object initialized, but not yet started.
func NewOpenUKArchive(e *Enumeration) *OpenUKArchive {
	o := &OpenUKArchive{
		baseURL:    "http://www.webarchive.org.uk/wayback/archive",
		SourceType: ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	o.BaseAmassService = *NewBaseAmassService(e, "OpenUKArchive", o)
	return o
}

// OnStart implements the AmassService interface
func (o *OpenUKArchive) OnStart() error {
	o.BaseAmassService.OnStart()

	go o.startRootDomains()
	go o.processRequests()
	return nil
}

func (o *OpenUKArchive) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range o.Enum().Config.Domains() {
		o.executeQuery(domain, domain)
	}
}

func (o *OpenUKArchive) processRequests() {
	for {
		select {
		case <-o.Quit():
			return
		case req := <-o.RequestChan():
			o.executeQuery(req.Name, req.Domain)
		}
	}
}

func (o *OpenUKArchive) executeQuery(sn, domain string) {
	if sn == "" || domain == "" {
		return
	}
	if o.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(o, o.baseURL, domain, sn)
	if err != nil {
		o.Enum().Log.Printf("%s: %v", o.String(), err)
		return
	}

	for _, name := range names {
		o.Enum().NewNameEvent(&AmassRequest{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    o.SourceType,
			Source: o.String(),
		})
	}
}
