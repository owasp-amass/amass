// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// Riddler is the Service that handles access to the Riddler data source.
type Riddler struct {
	core.BaseService

	SourceType string
}

// NewRiddler returns he object initialized, but not yet started.
func NewRiddler(config *core.Config, bus *core.EventBus) *Riddler {
	r := &Riddler{SourceType: core.SCRAPE}

	r.BaseService = *core.NewBaseService(r, "Riddler", config, bus)
	return r
}

// OnStart implements the Service interface
func (r *Riddler) OnStart() error {
	r.BaseService.OnStart()

	go r.processRequests()
	return nil
}

func (r *Riddler) processRequests() {
	for {
		select {
		case <-r.Quit():
			return
		case req := <-r.RequestChan():
			if r.Config().IsDomainInScope(req.Domain) {
				r.executeQuery(req.Domain)
			}
		}
	}
}

func (r *Riddler) executeQuery(domain string) {
	re := r.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	r.SetActive()
	url := r.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		r.Config().Log.Printf("%s: %s: %v", r.String(), url, err)
		return
	}

	for _, name := range re.FindAllString(page, -1) {
		r.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    r.SourceType,
			Source: r.String(),
		})
	}
}

func (r *Riddler) getURL(domain string) string {
	format := "https://riddler.io/search?q=pld:%s"

	return fmt.Sprintf(format, domain)
}
