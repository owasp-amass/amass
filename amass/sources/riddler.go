// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// Riddler is the AmassService that handles access to the Riddler data source.
type Riddler struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	SourceType string
}

// NewRiddler requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewRiddler(e *core.Enumeration, bus evbus.Bus, config *core.AmassConfig) *Riddler {
	r := &Riddler{
		Bus:        bus,
		Config:     config,
		SourceType: core.SCRAPE,
	}

	r.BaseAmassService = *core.NewBaseAmassService(e, "Riddler", r)
	return r
}

// OnStart implements the AmassService interface
func (r *Riddler) OnStart() error {
	r.BaseAmassService.OnStart()

	go r.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (r *Riddler) OnStop() error {
	r.BaseAmassService.OnStop()
	return nil
}

func (r *Riddler) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range r.Config.Domains() {
		r.executeQuery(domain)
	}
}

func (r *Riddler) executeQuery(domain string) {
	url := r.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		r.Config.Log.Printf("%s: %s: %v", r.String(), url, err)
		return
	}

	r.SetActive()
	re := r.Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		req := &core.AmassRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    r.SourceType,
			Source: r.String(),
		}

		if r.Enum().DupDataSourceName(req) {
			continue
		}
		r.Bus.Publish(core.NEWNAME, req)
	}
}

func (r *Riddler) getURL(domain string) string {
	format := "https://riddler.io/search?q=pld:%s"

	return fmt.Sprintf(format, domain)
}
