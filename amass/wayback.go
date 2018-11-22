// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"github.com/OWASP/Amass/amass/utils"
)

// Wayback is the AmassService that handles access to the Wayback data source.
type Wayback struct {
	BaseAmassService

	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewWayback returns he object initialized, but not yet started.
func NewWayback(e *Enumeration) *Wayback {
	w := &Wayback{
		baseURL:    "http://web.archive.org/web",
		SourceType: ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	w.BaseAmassService = *NewBaseAmassService(e, "Wayback", w)
	return w
}

// OnStart implements the AmassService interface
func (w *Wayback) OnStart() error {
	w.BaseAmassService.OnStart()

	w.Enum().Bus.SubscribeAsync(CHECKED, w.SendRequest, false)
	go w.startRootDomains()
	go w.processRequests()
	return nil
}

// OnStop implements the AmassService interface
func (w *Wayback) OnStop() error {
	w.BaseAmassService.OnStop()

	w.Enum().Bus.Unsubscribe(CHECKED, w.SendRequest)
	return nil
}

func (w *Wayback) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range w.Enum().Config.Domains() {
		w.executeQuery(domain, domain)
	}
}

func (w *Wayback) processRequests() {
	for {
		select {
		case <-w.Quit():
			return
		case req := <-w.RequestChan():
			w.executeQuery(req.Name, req.Domain)
		}
	}
}

func (w *Wayback) executeQuery(sn, domain string) {
	if sn == "" || domain == "" {
		return
	}
	if w.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(w, w.baseURL, domain, sn)
	if err != nil {
		w.Enum().Log.Printf("%s: %v", w.String(), err)
		return
	}

	for _, name := range names {
		req := &AmassRequest{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    w.SourceType,
			Source: w.String(),
		}

		if w.Enum().DupDataSourceName(req) {
			continue
		}
		w.Enum().Bus.Publish(NEWNAME, req)
	}
}
