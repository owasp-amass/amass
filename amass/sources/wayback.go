// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// Wayback is the Service that handles access to the Wayback data source.
type Wayback struct {
	core.BaseService

	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewWayback returns he object initialized, but not yet started.
func NewWayback(config *core.Config, bus *core.EventBus) *Wayback {
	w := &Wayback{
		baseURL:    "http://web.archive.org/web",
		SourceType: core.ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	w.BaseService = *core.NewBaseService(w, "Wayback", config, bus)
	return w
}

// OnStart implements the Service interface
func (w *Wayback) OnStart() error {
	w.BaseService.OnStart()

	w.Bus().Subscribe(core.NameResolvedTopic, w.SendRequest)
	go w.startRootDomains()
	go w.processRequests()
	return nil
}

func (w *Wayback) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range w.Config().Domains() {
		w.executeQuery(domain, domain)
	}
}

func (w *Wayback) processRequests() {
	for {
		select {
		case <-w.Quit():
			return
		case req := <-w.RequestChan():
			if w.Config().IsDomainInScope(req.Name) {
				w.executeQuery(req.Name, req.Domain)
			}
		}
	}
}

func (w *Wayback) executeQuery(sn, domain string) {
	if sn == "" || domain == "" || w.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(w, w.baseURL, domain, sn)
	if err != nil {
		w.Config().Log.Printf("%s: %v", w.String(), err)
		return
	}

	for _, name := range names {
		w.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    w.SourceType,
			Source: w.String(),
		})
	}
}
