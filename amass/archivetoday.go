// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"github.com/OWASP/Amass/amass/utils"
)

// ArchiveToday is the Service that handles access to the ArchiveToday data source.
type ArchiveToday struct {
	BaseService

	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewArchiveToday returns he object initialized, but not yet started.
func NewArchiveToday(e *Enumeration) *ArchiveToday {
	a := &ArchiveToday{
		baseURL:    "http://archive.is",
		SourceType: ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	a.BaseService = *NewBaseService(e, "ArchiveToday", a)
	return a
}

// OnStart implements the Service interface
func (a *ArchiveToday) OnStart() error {
	a.BaseService.OnStart()

	go a.startRootDomains()
	go a.processRequests()
	return nil
}

func (a *ArchiveToday) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range a.Enum().Config.Domains() {
		a.executeQuery(domain, domain)
	}
}

func (a *ArchiveToday) processRequests() {
	for {
		select {
		case <-a.Quit():
			return
		case req := <-a.RequestChan():
			a.executeQuery(req.Name, req.Domain)
		}
	}
}

func (a *ArchiveToday) executeQuery(sn, domain string) {
	if sn == "" || domain == "" {
		return
	}
	if a.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(a, a.baseURL, domain, sn)
	if err != nil {
		a.Enum().Log.Printf("%s: %v", a.String(), err)
		return
	}

	for _, name := range names {
		a.Enum().NewNameEvent(&Request{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    a.SourceType,
			Source: a.String(),
		})
	}
}
